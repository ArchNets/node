package core

import (
	"testing"

	"github.com/stretchr/testify/require"
	coreConf "github.com/xtls/xray-core/infra/conf"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestTLSConfigECH(t *testing.T) {
	serverKeys := "ACCA27lSajX65Lk3S+StKcQpatcWY6BVpKxm0i+uozSdNQBe/g0AWgAAIAAg4jj0tat/uQtKa+l5Uif275VgXeoQUG2W+0g1BdembRkAJAABAAEAAQACAAEAAwACAAEAAgACAAIAAwADAAEAAwACAAMAAwALZXhhbXBsZS5jb20AAA=="
	configList := "AF7+DQBaAAAgACDiOPS1q3+5C0pr6XlSJ/bvlWBd6hBQbZb7SDUF16ZtGQAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAAtleGFtcGxlLmNvbQAA"

	tlsConf := &coreConf.TLSConfig{
		ECHServerKeys: serverKeys,
		ECHConfigList: configList,
		MinVersion:    "1.3",
	}
	msg, err := tlsConf.Build()
	require.NoError(t, err)
	require.NotNil(t, msg)

	tlsMessage, ok := msg.(*xtls.Config)
	require.True(t, ok)
	require.NotEmpty(t, tlsMessage.EchServerKeys)
	require.Equal(t, configList, tlsMessage.EchConfigList)
}
