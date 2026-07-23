package core

import (
	"sync"
	"testing"
)

func TestEnsureTProxyIpRuleConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	concurrentCalls := 10

	wg.Add(concurrentCalls)
	for i := 0; i < concurrentCalls; i++ {
		go func() {
			defer wg.Done()
			ensureTProxyIpRule()
		}()
	}
	wg.Wait()
}
