package core

import (
	"fmt"

	"github.com/archnets/node/api/panel"
)

func (v *XrayCore) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := buildInbound(info, tag)
	if err != nil {
		return err
	}
	err = v.AddInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

// What changed: Added removal of tag + "_inner_ss" in DelNode before removing tag.
// Why: Ensures auto-provisioned inner Shadowsocks inbounds for ShadowTLS nodes are torn down together with the outer node.
func (v *XrayCore) DelNode(tag string) error {
	_ = v.RemoveInbound(tag + "_inner_ss")
	err := v.RemoveInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
