// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (c *Client) handleAsyncServerPacket(packet VpnProto.Packet, timeout time.Duration) error {
	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ_ACK:
		if c != nil && c.stream0Runtime != nil {
			c.stream0Runtime.ackDNSRequestFragment(packet)
		}
		return nil
	case Enums.PACKET_DNS_QUERY_RES:
		return c.handleInboundDNSResponseFragment(packet)
	default:
		return c.handleFollowUpServerPacket(packet, timeout)
	}
}

func (c *Client) pollServerPacketWithConnection(connection Connection, timeout time.Duration) (VpnProto.Packet, error) {
	payload, err := buildClientPingPayload()
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return c.sendSessionControlPacketWithConnection(connection, Enums.PACKET_PING, payload, timeout)
}

func buildClientPingPayload() ([]byte, error) {
	payload := []byte{'P', 'O', ':'}
	randomPart, err := randomBytes(4)
	if err != nil {
		return nil, err
	}
	return append(payload, randomPart...), nil
}

func matchesExpectedStreamResponse(sentType uint8, streamID uint16, sequenceNum uint16, packet VpnProto.Packet) bool {
	if packet.StreamID != streamID || packet.SequenceNum != sequenceNum {
		return false
	}

	switch sentType {
	case Enums.PACKET_STREAM_SYN:
		return packet.PacketType == Enums.PACKET_STREAM_SYN_ACK
	case Enums.PACKET_SOCKS5_SYN:
		return packet.PacketType == Enums.PACKET_SOCKS5_SYN_ACK || isSOCKS5ErrorPacket(packet.PacketType)
	case Enums.PACKET_STREAM_DATA:
		return packet.PacketType == Enums.PACKET_STREAM_DATA_ACK
	case Enums.PACKET_STREAM_FIN:
		return packet.PacketType == Enums.PACKET_STREAM_FIN_ACK
	case Enums.PACKET_STREAM_RST:
		return packet.PacketType == Enums.PACKET_STREAM_RST_ACK
	default:
		return false
	}
}
