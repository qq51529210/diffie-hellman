package diffie_hellman

import (
	"bytes"
	"testing"
)

func Test_DiffieHellman(t *testing.T) {
	keyLen := 32
	// 1. 生成本地的随机数
	clientRandom := RandomInt(keyLen)
	serverRandom := RandomInt(keyLen)
	// 2. 生成交换密钥
	clientExchangeKey := make([]byte, keyLen)
	GenExchangeKey(clientRandom, clientExchangeKey)
	serverExchangeKey := make([]byte, keyLen)
	GenExchangeKey(serverRandom, serverExchangeKey)
	// 3. 生成加密密钥
	clientCryptoKey := make([]byte, keyLen)
	GenCryptoKey(serverExchangeKey, clientCryptoKey, clientRandom)
	serverCryptoKey := make([]byte, keyLen)
	GenCryptoKey(clientExchangeKey, serverCryptoKey, serverRandom)
	// 比较双方生成的密钥，应该是一样的
	if bytes.Compare(clientCryptoKey, serverCryptoKey) != 0 {
		t.FailNow()
	}
	// 有一个黑客
	hackerRandom := RandomInt(keyLen)
	// 获取到了server的交换key
	hackerCryptoKey := make([]byte, keyLen)
	GenCryptoKey(serverExchangeKey, hackerCryptoKey, hackerRandom)
	// 要冒充，生成的密钥是不一致的
	if bytes.Compare(serverCryptoKey, hackerCryptoKey) == 0 {
		t.FailNow()
	}
}
