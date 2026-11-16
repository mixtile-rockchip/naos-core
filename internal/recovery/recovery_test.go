package recovery

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRecordVersion3Format(t *testing.T) {
	data := record()
	payload := []byte("NAOS-RECOVERY\nversion=3\noperation=clear-userdata")
	if len(data) != Size || !bytes.Equal(data[:len(payload)], payload) {
		t.Fatal("unexpected recovery payload or record size")
	}
	if !bytes.Equal(data[len(payload):256], bytes.Repeat([]byte{' '}, 256-len(payload))) {
		t.Fatal("recovery payload padding is not spaces")
	}
	if string(data[256:320]) != "0bc4849d3f7f3c40fbfb44c1d2438ae37ef62775a782bc24d175a061cf84dd36" {
		t.Fatal("unexpected recovery checksum")
	}
	if !bytes.Equal(data[320:], make([]byte, 192)) {
		t.Fatal("recovery suffix is not zero")
	}
}

func fixture(t *testing.T, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "misc.img")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestArmOnlyAssignedSectorAndIdempotent(t *testing.T) {
	before := bytes.Repeat([]byte{0xa5}, miscBytes)
	clear(before[Offset : Offset+Size])
	f := fixture(t, before)
	wanted := record()
	for i := 0; i < 2; i++ {
		if err := arm(f, wanted); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	expected := bytes.Clone(before)
	copy(expected[Offset:Offset+Size], wanted)
	if !bytes.Equal(after, expected) {
		t.Fatal("write changed bytes outside assigned sector")
	}
}

func TestArmRejectsUnknownCorruptAndShortReads(t *testing.T) {
	wanted := record()
	cases := map[string][]byte{}
	unknown := make([]byte, miscBytes)
	unknown[Offset] = 1
	cases["unknown"] = unknown
	damaged := make([]byte, miscBytes)
	copy(damaged[Offset:], wanted)
	damaged[Offset+20] ^= 1
	cases["damaged"] = damaged
	cases["short"] = make([]byte, Offset+Size-1)
	for name, before := range cases {
		t.Run(name, func(t *testing.T) {
			f := fixture(t, before)
			if err := arm(f, wanted); err == nil {
				t.Fatal("accepted invalid existing record")
			}
			after, _ := os.ReadFile(f.Name())
			if !bytes.Equal(after, before) {
				t.Fatal("rejected request changed misc")
			}
		})
	}
}

func TestShellAndGoUseIdenticalRecord(t *testing.T) {
	script, err := filepath.Abs("../../../meta-naos/recipes-core/initramfs/files/recovery.sh")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "record.bin")
	output, err := exec.Command("sh", "-c", `. "$1"; naos_recovery_record "$2"`, "sh", script, target).CombinedOutput()
	if err != nil {
		t.Fatalf("shell record: %v %s", err, output)
	}
	actual, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	wanted := record()
	if !bytes.Equal(actual, wanted) {
		t.Fatal("Go and ramdisk recovery records differ")
	}
}
