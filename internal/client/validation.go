// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import "masterdnsvpn-go/internal/enums"
import VPNProto "masterdnsvpn-go/internal/vpnproto"

func isPreSessionResponseType(packetType uint8) bool {
	switch packetType {
	case enums.PacketMTUUpRes, enums.PacketMTUDownRes, enums.PacketSessionAccept:
		return true
	default:
		return false
	}
}

func (c *Client) validateServerPacket(packet VPNProto.Packet) bool {
	if isPreSessionResponseType(packet.PacketType) {
		return true
	}
	if c == nil || c.sessionID == 0 {
		return false
	}
	return packet.SessionID == c.sessionID && packet.SessionCookie == c.sessionCookie
}
