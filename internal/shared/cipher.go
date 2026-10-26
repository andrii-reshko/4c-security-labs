package shared

// Result is what every lab's cipher returns from Encrypt. Meta carries
// algorithm-specific side information decryption needs back (lab 1's
// columnar cipher uses it for the padding count, section 6.2 table); labs
// that never populate it just leave it nil.
type Result struct {
	Text string
	Meta map[string]string
}
