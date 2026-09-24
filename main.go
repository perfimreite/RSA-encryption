package main

import (
	"crypto/rand"
	"fmt"
	"math"
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
	n uint64
	d uint64
}

type Person struct {
	name             string
	message          string
	messagesReceived []EncryptedMessage
	key              Key
	pubKeys          map[string]uint64
}

const e = 65537

func (p Person) transmitPublicKey() uint64 {
	return p.key.n
}

func generatePrimePair(bitSize int, difference int) (uint64, uint64) {
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	for {
		q, err := rand.Prime(rand.Reader, bitSize)
		if err != nil {
			panic(err)
		}
		if math.Abs(float64(p.Int64()-q.Int64())) > float64(difference) {
			return p.Uint64(), q.Uint64()
		}
	}
}

// euclidean algorithm: https://en.wikipedia.org/wiki/Euclidean_algorithm
// finds greatest common divisor of a and b
func gcd(a, b uint64) uint64 {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}

// least common multiple (lcm): https://en.wikipedia.org/wiki/Least_common_multiple
// smallest number that is divisible by both a and b
func lcm(a, b uint64) uint64 {
	assert(a != 0 && b != 0, "Division by zero is not allowed")
	return uint64(math.Abs(float64(a)) * (math.Abs(float64(b)) / float64(gcd(a, b))))
}

// extended euclidian algorithm: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
func extendedGcd(a, b uint64) uint64 {
	// (x * a + b * y = 1)
	//
	// function extended_gcd(a, b)
	//     (old_r, r) := (a, b)
	//     (old_s, s) := (1, 0)
	//     (old_t, t) := (0, 1)
	//
	//     while r ≠ 0 do
	//         quotient := old_r div r
	//         (old_r, r) := (r, old_r − quotient × r)
	//         (old_s, s) := (s, old_s − quotient × s)
	//         (old_t, t) := (t, old_t − quotient × t)
	//
	//     output "Bézout coefficients:", (old_s, old_t)
	//     output "greatest common divisor:", old_r
	//     output "quotients by the gcd:", (t, s)

	oldR, r := int64(a), int64(b)
	oldS, s := int64(1), int64(0)
	// oldT, t := int64(0), int64(1)

	for r != 0 {
		quotient := int64(math.Floor(float64(oldR / r)))
		oldR, r = r, oldR-quotient*r
		oldS, s = s, oldS-quotient*s
		// oldT, t = t, oldT - quotient * t
	}

	if oldS < 0 {
		return uint64(oldS + int64(b))
	}
	return uint64(oldS)
}

func generateKey() Key {
	// NOTE: weird behavoir occurs when bitSize is set to 32,
	//       decryption is not correct.
	p, q := generatePrimePair(24, 1e4)

	n := p * q
	mod := lcm(p-1, q-1)

	// common values for e: 3, 5, 17, 65537 (2**16 + 1)
	e := uint64(65537)
	assert(1 < e && e < mod, "e should be in this interval")
	assert(gcd(e, mod) == 1, "e and m should be coprime (no common multiples other than 1)")

	d := extendedGcd(e, mod)
	assert(d >= 0, "d should not be a negative number")

	key := Key{}

	key.n = n
	key.d = d

	return key
}

func bigIntExpMod(base big.Int, exp uint64, mod uint64) *big.Int {
	return base.Exp(&base, new(big.Int).SetUint64(exp), new(big.Int).SetUint64(mod))
}

const paddedPlainTextSize = 6

func padPlainTextMessage(msg string) []byte {
	for i := len(msg); i < paddedPlainTextSize; i++ {
		msg += string('\x00')
	}
	return []byte(msg)
}

func unpadPlainTextMessage(msg []byte) string {
	assert(len(msg) == paddedPlainTextSize, fmt.Sprintf("The padded message should be %v chars long\n", paddedPlainTextSize))
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
	assert(0 <= m.Cmp(big.NewInt(0)) && m.Cmp(new(big.Int).SetUint64(nReceiver)) < 0, "m should be in this interval")

	c := bigIntExpMod(*m, e, nReceiver)
	s := bigIntExpMod(*m, p.key.d, p.key.n)

	return EncryptedMessage{
		c:         new(big.Int).Set(c),
		signature: s,
		sender:    p.name,
	}, true
}

func (p Person) decryptMessage() (string, bool) {
	assert(len(p.messagesReceived) >= 1, "p should always have a message if this method has been called")
	encMsg := p.messagesReceived[0]

	m := bigIntExpMod(*encMsg.c, p.key.d, p.key.n)

	nSender, ok := p.pubKeys[encMsg.sender]
	if !ok {
		return "", false
	}

	s := bigIntExpMod(*encMsg.signature, e, nSender)

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
		message:          "Hi Bob", // Max char size is 6
		messagesReceived: make([]EncryptedMessage, 0),
		key:              generateKey(),
		pubKeys:          make(map[string]uint64),
	}

	b := Person{
		name:             "Bob",
		message:          "Wasup!", // Max char size is 6
		messagesReceived: make([]EncryptedMessage, 0),
		key:              generateKey(),
		pubKeys:          make(map[string]uint64),
	}

	fmt.Printf("%v: n=%v e=%v d=%v - %v\n", a.name, a.key.n, e, a.key.d, a.message)
	fmt.Printf("%v: n=%v e=%v d=%v - %v\n", b.name, b.key.n, e, b.key.d, b.message)

	//////////////////////////////////
	// key distribution

	a.pubKeys[b.name] = b.transmitPublicKey()
	b.pubKeys[a.name] = a.transmitPublicKey()

	//////////////////////////////////
	// encrypction

	encMsg, ok := a.encryptMessage(b.name)
	if !ok {
		fmt.Println("Enctryption of message failed")
		return
	}
	b.messagesReceived = append(b.messagesReceived, encMsg)

	//////////////////////////////////
	// decryption

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
