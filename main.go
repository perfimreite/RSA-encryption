package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func assert(statement bool, message string) {
	if !statement {
		panic("Assert failed: " + message)
	}
}

type EncryptedMessage struct {
	c         *big.Int
	signature *big.Int
	sender    string
}

type Key struct {
	n *big.Int
	d *big.Int
}

type Person struct {
	name             string
	message          string
	messagesReceived []EncryptedMessage
	key              Key
	pubKeys          map[string]*big.Int
}

const e = 65537

func (p Person) transmitPublicKey() *big.Int {
	return p.key.n
}

func generatePrimePair(bitSize int, difference uint64) (*big.Int, *big.Int) {
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	for {
		q, err := rand.Prime(rand.Reader, bitSize)
		if err != nil {
			panic(err)
		}
		if new(big.Int).Abs(new(big.Int).Sub(p, q)).Cmp(new(big.Int).SetUint64(difference)) > 0 {
			return p, q
		}
	}
}

func gcd(a, b *big.Int) *big.Int {
	return new(big.Int).GCD(nil, nil, a, b)
}

func lcm(a, b *big.Int) *big.Int {
	assert(a.Sign() != 0 && b.Sign() != 0, "Division by zero is not allowed")

	g := gcd(a, b)
	result := new(big.Int).Mul(a, b)
	return result.Div(result, g)
}

func extendedGcd(a, b *big.Int) *big.Int {
	x := new(big.Int)
	g := new(big.Int)

	g.GCD(x, nil, a, b)

	if g.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	return x.Mod(x, b)
}

func generateKey() Key {
	p, q := generatePrimePair(256, 1e9)

	n := new(big.Int).Mul(p, q)

	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	qMinusOne := new(big.Int).Sub(q, big.NewInt(1))

	mod := lcm(pMinusOne, qMinusOne)

	eBigInt := big.NewInt(e)

	assert(eBigInt.Cmp(big.NewInt(1)) > 0 && eBigInt.Cmp(mod) < 0, "e should be in this interval")
	assert(gcd(eBigInt, mod).Cmp(big.NewInt(1)) == 0, "e and m should be coprime (no common multiples other than 1)")

	d := new(big.Int).ModInverse(eBigInt, mod)
	assert(d != nil, "Modular inverse does not exist")

	return Key{
		n: n,
		d: d,
	}
}

const paddedPlainTextSize = 6

func padPlainTextMessage(msg string) []byte {
	for i := len(msg); i < paddedPlainTextSize; i++ {
		msg += string('\x00')
	}
	return []byte(msg)
}

func unpadPlainTextMessage(msg []byte) string {
	// assert(len(msg) == paddedPlainTextSize, fmt.Sprintf("The padded message should be %v chars long\n", paddedPlainTextSize))
	for i := paddedPlainTextSize - 1; i >= 0; i-- {
		if msg[i] == '\x00' {
			msg = msg[0:i]
		}
	}
	return string(msg)
}

func (p Person) encryptMessage(receiverName string) (EncryptedMessage, bool) {
	nReceiver, ok := p.pubKeys[receiverName]
	if !ok {
		return EncryptedMessage{}, false
	}

	paddedMsg := padPlainTextMessage(p.message)

	m := new(big.Int)
	m.SetBytes(paddedMsg)
	assert(m.Cmp(big.NewInt(0)) >= 0 && m.Cmp(nReceiver) < 0, "m should be in this interval")

	c := new(big.Int).Exp(m, big.NewInt(e), nReceiver)
	s := new(big.Int).Exp(m, p.key.d, p.key.n)

	return EncryptedMessage{
		c:         c,
		signature: s,
		sender:    p.name,
	}, true
}

func (p Person) decryptMessage() (string, bool) {
	assert(len(p.messagesReceived) >= 1, "p should always have a message if this method has been called")
	encMsg := p.messagesReceived[0]

	m := new(big.Int).Exp(encMsg.c, p.key.d, p.key.n)

	nSender, ok := p.pubKeys[encMsg.sender]
	if !ok {
		return "", false
	}

	s := new(big.Int).Exp(encMsg.signature, big.NewInt(e), nSender)

	if s.Cmp(m) != 0 {
		return "", false
	}

	msg := unpadPlainTextMessage(m.Bytes())
	return msg, true
}

func main() {
	//////////////////////////////////
	// key generation

	a := Person{
		name:             "Alice",
		message:          "Hi Bob",
		messagesReceived: make([]EncryptedMessage, 0),
		key:              generateKey(),
		pubKeys:          make(map[string]*big.Int),
	}

	b := Person{
		name:             "Bob",
		message:          "In the beginning God created the heavens and the earth.",
		messagesReceived: make([]EncryptedMessage, 0),
		key:              generateKey(),
		pubKeys:          make(map[string]*big.Int),
	}

	fmt.Printf("%v:\n\tn=%v\n\te=%v\n\td=%v\n\tmsg=%v\n", a.name, a.key.n, e, a.key.d, a.message)
	fmt.Printf("%v:\n\tn=%v\n\te=%v\n\td=%v\n\tmsg=%v\n", b.name, b.key.n, e, b.key.d, b.message)

	//////////////////////////////////
	// key distribution

	a.pubKeys[b.name] = b.transmitPublicKey()
	b.pubKeys[a.name] = a.transmitPublicKey()

	//////////////////////////////////
	// encryption

	{
		encMsg, ok := b.encryptMessage(a.name)
		if !ok {
			fmt.Println("Encryption of message failed")
			return
		}
		a.messagesReceived = append(a.messagesReceived, encMsg)
	}

	{
		encMsg, ok := a.encryptMessage(b.name)
		if !ok {
			fmt.Println("Encryption of message failed")
			return
		}
		b.messagesReceived = append(b.messagesReceived, encMsg)
	}

	//////////////////////////////////
	// decryption

	for range a.messagesReceived {
		decMsg, ok := a.decryptMessage()
		if !ok {
			fmt.Println("Decryption of message failed")
			return
		}
		fmt.Println("Decrypted message:", decMsg)

		a.messagesReceived = a.messagesReceived[1:]
	}

	for range b.messagesReceived {
		decMsg, ok := b.decryptMessage()
		if !ok {
			fmt.Println("Decryption of message failed")
			return
		}
		fmt.Println("Decrypted message:", decMsg)

		b.messagesReceived = b.messagesReceived[1:]
	}
}
