package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Rotchamar/dhcp/dhcpv4"
	"github.com/Rotchamar/dhcp/dhcpv4/nclient4"
	"github.com/u-root/uio/uio"
	"github.com/vishvananda/netlink"
)

type DHCPState uint8

const (
	StateAllocating DHCPState = iota
	StateBound
	StateRenewing
	StateRebinding
)

var (
	iface = flag.String("i", "enp1s0np1np1", "Interface to configure via DHCPv4")

	client            *nclient4.Client
	nextState         DHCPState = StateAllocating
	lease             nclient4.Lease
	ctx               context.Context
	ctxCancel         context.CancelFunc
	t0                time.Time
	t1                time.Time
	t2                time.Time
	link              netlink.Link
	awaitingAckNak    bool
	udpConn           *net.UDPConn
	listenUDP         bool
	udpListenerReturn chan *dhcpv4.DHCPv4
)

type AuthenticationOption struct {
	// Code            uint8
	// Length          uint8
	Protocol        uint8
	Algorithm       dhcpv4.AlgorithmType
	RDM             uint8
	ReplayDetection uint64
	AuthInfo        AuthenticationInformation
}

type AuthenticationInformation struct {
	Type  uint8
	Value [16]byte
}

func (a AuthenticationOption) ToBytes() []byte {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.BigEndian, a)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func (a AuthenticationOption) String() string {
	switch a.AuthInfo.Type {
	case 1:
		return fmt.Sprintf("Forcerenew Nonce Value: %x\n", a.AuthInfo.Value)
	case 2:
		return fmt.Sprintf("HMAC-MD5 digest: %x\n", a.AuthInfo.Value)
	default:
		return fmt.Sprintf("Unknown Authentication Information Type value: %d", a.AuthInfo.Type)
	}
}

func FromBytes(q []byte) AuthenticationOption {
	var a AuthenticationOption
	buf := uio.NewBigEndianBuffer(q)

	a.Protocol = buf.Read8()
	a.Algorithm = dhcpv4.AlgorithmType(buf.Read8())
	a.RDM = buf.Read8()
	a.ReplayDetection = buf.Read64()
	a.AuthInfo.Type = buf.Read8()
	a.AuthInfo.Value = [16]byte(buf.CopyN(16))

	return a
}

func insertForceRenewCapable() dhcpv4.Modifier {
	return func(d *dhcpv4.DHCPv4) {
		d.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionForcerenewNonceCapable, Value: dhcpv4.AlgorithmHMAC_MD5})
	}

}

func removeExistingIfaceAddrs() error {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}

	if len(addrs) != 0 {
		log.Printf("Removing current IPv4 address(es) on interface %s", *iface)

		for _, addr := range addrs {
			err = netlink.AddrDel(link, &addr)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func sendRelease() error {
	release, err := dhcpv4.NewReleaseFromACK(lease.ACK)
	if err != nil {
		return err
	}

	_, err = udpConn.WriteTo(release.ToBytes(), &net.UDPAddr{IP: lease.ACK.ServerIPAddr, Port: 67})
	if err != nil {
		return err
	}

	time.Sleep(50 * time.Millisecond) // Wait enough for ARP to resolve before removing interface address

	err = removeExistingIfaceAddrs()
	if err != nil {
		return err
	}

	return nil
}

func sendRenew() error {
	request, err := dhcpv4.NewRenewFromAck(lease.ACK,
		dhcpv4.WithOption(dhcpv4.OptMaxMessageSize(dhcpv4.MaxMessageSize)),
		insertForceRenewCapable())
	if err != nil {
		return err
	}

	log.Printf("sent message: %s", request)
	_, err = udpConn.WriteTo(request.ToBytes(), &net.UDPAddr{IP: lease.ACK.ServerIPAddr, Port: 67})
	if err != nil {
		return err
	}

	return nil
}

func processRenewRebindResponse(response *dhcpv4.DHCPv4) error {
	var err error

	switch response.MessageType() {
	case dhcpv4.MessageTypeAck:
		// TODO: check IP address is unused

		if !net.IP.Equal(response.GatewayIPAddr, lease.ACK.GatewayIPAddr) {
			err = netlink.RouteReplace(&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst: &net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				},
				Gw: lease.ACK.GatewayIPAddr,
			})
			if err != nil {
				return err
			}
		}

		lease.ACK = response
		lease.CreationTime = time.Now()

		nextState = StateBound

	case dhcpv4.MessageTypeNak:
		err := removeExistingIfaceAddrs()
		if err != nil {
			return err
		}

		nextState = StateAllocating
	}

	awaitingAckNak = false // No actual need for this here, just for peace of mind
	listenUDP = false
	udpConn.Close()

	return nil
}

func dhcpUDPListener() {

	for listenUDP {
		buf := make([]byte, 2048)
		n, _, err := udpConn.ReadFrom(buf)
		if err != nil {
			continue
		}
		incommingMsg, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}

		log.Printf("received message: %s", incommingMsg)
		if incommingMsg.MessageType() == dhcpv4.MessageTypeForceRenew {

			authOption := FromBytes(incommingMsg.Options[dhcpv4.OptionAuthentication.Code()])

			receivedDigest := authOption.AuthInfo.Value
			authOption.AuthInfo.Value = [16]byte{}

			incommingMsg.Options.Update(dhcpv4.Option{
				Code:  dhcpv4.OptionAuthentication,
				Value: authOption,
			})

			nonce := FromBytes(lease.ACK.Options[dhcpv4.OptionAuthentication.Code()]).AuthInfo.Value

			hmacmd5 := hmac.New(md5.New, nonce[:])
			_, err = hmacmd5.Write(incommingMsg.ToBytes())
			if err != nil {
				continue
			}
			calculatedDigest := hmacmd5.Sum(nil)

			fmt.Println(receivedDigest)
			fmt.Println(calculatedDigest)
			if !bytes.Equal(receivedDigest[:], calculatedDigest) {
				continue
			}

			sendRenew()
			awaitingAckNak = true
			continue
		}
		if awaitingAckNak &&
			(incommingMsg.MessageType() == dhcpv4.MessageTypeAck ||
				incommingMsg.MessageType() == dhcpv4.MessageTypeNak) {
			udpListenerReturn <- incommingMsg
		}

	}
}

func Allocating() error {
	// RFC 2131, Section 4.4.1, Table 5 details what a DISCOVER packet should
	// contain.
	discover, err := client.CreateDiscover(dhcpv4.WithOption(dhcpv4.OptMaxMessageSize(dhcpv4.MaxMessageSize)),
		insertForceRenewCapable())
	if err != nil {
		return fmt.Errorf("unable to create a discovery request: %w", err)
	}

	offer, err := client.SendAndRead(ctx, client.RemoteAddr(), discover,
		nclient4.IsAll(nclient4.IsMessageType(dhcpv4.MessageTypeOffer), nclient4.IsForcerenewNonceCapable()))
	if err == nclient4.ErrNoResponse {
		time.Sleep(5 * time.Second)
		return nil
	}
	if err != nil {
		return fmt.Errorf("got an error while the discovery request: %w", err)
	}

	request, err := dhcpv4.NewRequestFromOffer(offer,
		dhcpv4.WithOption(dhcpv4.OptMaxMessageSize(nclient4.MaxMessageSize)),
		insertForceRenewCapable())
	if err != nil {
		return fmt.Errorf("unable to create a request: %w", err)
	}

	// (correctServer AND ((ack AND hasNonceAuth) OR nack))
	response, err := client.SendAndRead(ctx, client.RemoteAddr(), request, nclient4.IsAll(
		nclient4.IsCorrectServer(offer.ServerIdentifier()),
		nclient4.IsSome(
			nclient4.IsAll(
				nclient4.IsMessageType(dhcpv4.MessageTypeAck),
				nclient4.HasOption(dhcpv4.OptionAuthentication), // TODO: meter la recepción del nonceauthentication
				// Este TODO es opcional, ya que sabemos que esta opción siempre está bien construida, pero se podría
				// mejorar (ahora solo verificamos que la cabecera existe)
			),
			nclient4.IsMessageType(dhcpv4.MessageTypeNak),
		)))
	if err == nclient4.ErrNoResponse {
		time.Sleep(5 * time.Second)
		return nil
	}
	if err != nil {
		return fmt.Errorf("got an error while processing the request: %w", err)
	}
	if response.MessageType() == dhcpv4.MessageTypeNak {
		return nil
	}

	// TODO: check IP address is unused

	lease.ACK = response
	lease.Offer = offer
	lease.CreationTime = time.Now()

	nextState = StateBound
	return nil
}

/*
	func Bound() error {
		t0 = lease.CreationTime.Add(time.Second * time.Duration(binary.BigEndian.Uint32(lease.ACK.Options[dhcpv4.OptionIPAddressLeaseTime.Code()])))
		t1 = lease.CreationTime.Add(time.Second * time.Duration(0.5*float64(binary.BigEndian.Uint32(lease.ACK.Options[dhcpv4.OptionIPAddressLeaseTime.Code()]))))
		t2 = lease.CreationTime.Add(time.Second * time.Duration(0.875*float64(binary.BigEndian.Uint32(lease.ACK.Options[dhcpv4.OptionIPAddressLeaseTime.Code()]))))

		ipConfig := &netlink.Addr{IPNet: &net.IPNet{
			IP:   lease.ACK.YourIPAddr,
			Mask: lease.ACK.SubnetMask(),
		}}

		var err error
		if err = netlink.AddrReplace(link, ipConfig); err != nil {
			return err
		}

		ipRoute := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   net.ParseIP("0.0.0.0"),
				Mask: net.CIDRMask(0, 32),
			},
			Gw: lease.ACK.Options[dhcpv4.OptionClasslessStaticRoute.Code()][1:],
		}

		if err = netlink.RouteReplace(ipRoute); err != nil {
			return err
		}

		// ------
		listenUDP = true
		awaitingAckNak = false

		localAddr := net.UDPAddr{IP: lease.ACK.YourIPAddr, Port: 68}
		udpConn, err = net.ListenUDP("udp", &localAddr)
		if err != nil {
			return err
		}

		go dhcpUDPListener()
		// ------

		select {
		case <-time.After(time.Until(t1)):
			nextState = StateRenewing

		case response := <-udpListenerReturn: // This case will only happen after a forcerenew-request-ack/nak interaction
			err = processRenewRebindResponse(response)
			if err != nil {
				return err
			}
		}

		return nil
	}
*/
func Bound() error {
	var err error
	t0 = lease.CreationTime.Add(time.Second * time.Duration(binary.BigEndian.Uint32(lease.ACK.Options[dhcpv4.OptionIPAddressLeaseTime.Code()])))
	t1 = lease.CreationTime.Add(time.Second * time.Duration(0.5*float64(binary.BigEndian.Uint32(lease.ACK.Options[dhcpv4.OptionIPAddressLeaseTime.Code()]))))
	t2 = lease.CreationTime.Add(time.Second * time.Duration(0.875*float64(binary.BigEndian.Uint32(lease.ACK.Options[dhcpv4.OptionIPAddressLeaseTime.Code()]))))

	log.Printf("Entrando en Bound. IP ofrecida por servidor: %s", lease.ACK.YourIPAddr.String())

	// Levantar la interfaz por si no está UP
	if err := netlink.LinkSetUp(link); err != nil {
		log.Printf("Failed to set link up: %v", err)
		return err
	}

	// Mostrar IPs actuales
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	for _, a := range addrs {
		log.Printf("IP existente antes de reemplazo: %s", a.IP.String())
	}

	ipConfig := &netlink.Addr{IPNet: &net.IPNet{
		IP:   lease.ACK.YourIPAddr,
		Mask: lease.ACK.SubnetMask(),
	}}

	ones, _ := ipConfig.IPNet.Mask.Size()
	log.Printf("Mask size: %d", ones)
	if err := netlink.AddrReplace(link, ipConfig); err != nil {
		log.Printf("Failed to set IP address: %v", err)
		return err
	}

	// Verificar IP tras reemplazo
	addrsAfter, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	for _, a := range addrsAfter {
		log.Printf("IP activa tras replace: %s", a.IP.String())
	}

	// Añadir la ruta si está bien especificada la opción
	routeOpt := lease.ACK.Options[dhcpv4.OptionClasslessStaticRoute.Code()]
	if len(routeOpt) >= 5 {
		routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		if err != nil {
			log.Printf("Error listing routes: %v", err)
			return err
		}

		alreadyHasDefault := false
		for _, r := range routes {
			if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
				if r.LinkIndex != link.Attrs().Index {
					alreadyHasDefault = true
					break
				}
			}
		}

		if !alreadyHasDefault {
			ipRoute := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst: &net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.CIDRMask(0, 32),
				},
				Gw: net.IP(routeOpt[1:5]),
			}

			if err := netlink.RouteReplace(ipRoute); err != nil {
				log.Printf("Failed to set default route: %v", err)
				return err
			}
			log.Printf("Ruta por defecto añadida a %s", *iface)
		} else {
			log.Println("Ya existe una ruta por defecto en otra interfaz, no se modifica")
		}
	} else {
		log.Println("Skipping route configuration: ClasslessStaticRoute option missing or invalid")
	}
	// Iniciar escucha por ForceRenew
	listenUDP = true
	awaitingAckNak = false

	localAddr := net.UDPAddr{IP: lease.ACK.YourIPAddr, Port: 68}
	udpConn, err = net.ListenUDP("udp", &localAddr)
	if err != nil {
		return err
	}

	go dhcpUDPListener()

	select {
	case <-time.After(time.Until(t1)):
		nextState = StateRenewing

	case response := <-udpListenerReturn: // ForceRenew
		if err := processRenewRebindResponse(response); err != nil {
			return err
		}
	}

	return nil
}

func Renewing() error {
	awaitingAckNak = true

	err := sendRenew() // TODO: RFC 2131 4.4.5: Se puede mandar un segundo request antes de que expire el timer
	if err != nil {
		return err
	}

	select { // Send REQUEST to leasing server and wait for response (ACK/NACK) or timer
	case <-time.After(time.Until(t2)):
		nextState = StateRebinding
	case response := <-udpListenerReturn:
		err = processRenewRebindResponse(response)
		if err != nil {
			return err
		}
	}

	return nil
}

func Rebinding() error {

	c := make(chan *dhcpv4.DHCPv4, 1)
	e := make(chan error, 1)

	go func() {
		request, err := dhcpv4.NewRenewFromAck(lease.ACK,
			dhcpv4.WithOption(dhcpv4.OptMaxMessageSize(dhcpv4.MaxMessageSize)),
			insertForceRenewCapable())
		if err != nil {
			e <- err
			return
		}

		response, err := client.SendAndRead(ctx, client.RemoteAddr(), request, nclient4.IsAll(
			nclient4.IsCorrectServer(lease.Offer.ServerIdentifier()),
			nclient4.IsSome(
				nclient4.IsMessageType(dhcpv4.MessageTypeAck),
				nclient4.IsMessageType(dhcpv4.MessageTypeNak),
			)))
		if err == nclient4.ErrNoResponse {
			return
		}
		if err != nil {
			e <- fmt.Errorf("got an error while processing the request: %w", err)
			return
		}
		c <- response
	}()

	select {
	case <-time.After(time.Until(t0)):
		err := removeExistingIfaceAddrs()
		if err != nil {
			return err
		}

		awaitingAckNak = false // No actual need for this here, just for peace of mind
		listenUDP = false
		udpConn.Close()

		nextState = StateAllocating

	case response := <-udpListenerReturn:
		err := processRenewRebindResponse(response)
		if err != nil {
			return err
		}

	case response := <-c:
		processRenewRebindResponse(response)
		err := processRenewRebindResponse(response)
		if err != nil {
			return err
		}

	case err := <-e:
		return err
	}

	return nil
}

// func Release() {
// 	dhcpv4.NewReleaseFromACK()
// }

func mainDHCPLogic() {
	log.Println("Iniciando mainDHCPLogic()")

	mainCtx := context.Background()

	flag.Parse()

	var err error

	link, err = netlink.LinkByName(*iface)
	if err != nil {
		log.Printf("Error al obtener interfaz %s: %v", *iface, err)
		return
	}
	log.Printf("Interfaz encontrada: %s", link.Attrs().Name)

	err = removeExistingIfaceAddrs()
	if err != nil {
		log.Printf("Error al borrar direcciones previas: %v", err)
		return
	}
	log.Printf("Direcciones antiguas eliminadas de %s", *iface)

	// defer sendRelease()
	log.Println("Cliente DHCPv4 arrancando...")

	client, err = nclient4.New(*iface, nclient4.WithSummaryLogger(), nclient4.WithRetry(1), nclient4.WithTimeout(3*time.Second))
	if err != nil {
		log.Printf("Error creando cliente DHCP: %v", err)
		return
	}
	defer client.Close()

	ctx, ctxCancel = context.WithCancel(mainCtx)
	defer ctxCancel()

	udpListenerReturn = make(chan *dhcpv4.DHCPv4, 1)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	e := make(chan error, 1)

	log.Println("Entrando en bucle de estados DHCP")
	go func() {
		for {
			log.Printf("Estado actual: %v", nextState)
			switch nextState {
			case StateAllocating:
				err = Allocating()
				if err != nil {
					e <- fmt.Errorf("error in allocating stage: %w", err)
					return
				}
			case StateBound:
				err = Bound()
				if err != nil {
					e <- fmt.Errorf("error in bound stage: %w", err)
					return
				}
			case StateRenewing:
				err = Renewing()
				if err != nil {
					e <- fmt.Errorf("error in renewing stage: %w", err)
					return
				}
			case StateRebinding:
				err = Rebinding()
				if err != nil {
					e <- fmt.Errorf("error in rebinding stage: %w", err)
					return
				}
			}
		}
	}()

	select {
	case <-c:
	case err = <-e:
		log.Printf("Error detectado: %v", err)
	}
}
