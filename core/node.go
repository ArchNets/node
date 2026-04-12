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

func (v *XrayCore) DelNode(tag string) error {
	err := v.RemoveInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
