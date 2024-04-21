package arch

import gapstone "github.com/knightsc/gapstone"

var regNameMap = map[uint]string{
	gapstone.X86_REG_INVALID: "REG_INVALID",
	gapstone.X86_REG_AH:      "REG_AH",
	gapstone.X86_REG_AL:      "REG_AL",
	gapstone.X86_REG_AX:      "REG_AX",
	gapstone.X86_REG_BH:      "REG_BH",
	gapstone.X86_REG_BL:      "REG_BL",
	gapstone.X86_REG_BP:      "REG_BP",
	gapstone.X86_REG_BPL:     "REG_BPL",
	gapstone.X86_REG_BX:      "REG_BX",
	gapstone.X86_REG_CH:      "REG_CH",
	gapstone.X86_REG_CL:      "REG_CL",
	gapstone.X86_REG_CS:      "REG_CS",
	gapstone.X86_REG_CX:      "REG_CX",
	gapstone.X86_REG_DH:      "REG_DH",
	gapstone.X86_REG_DI:      "REG_DI",
	gapstone.X86_REG_DIL:     "REG_DIL",
	gapstone.X86_REG_DL:      "REG_DL",
	gapstone.X86_REG_DS:      "REG_DS",
	gapstone.X86_REG_DX:      "REG_DX",
	gapstone.X86_REG_EAX:     "REG_EAX",
	gapstone.X86_REG_EBP:     "REG_EBP",
	gapstone.X86_REG_EBX:     "REG_EBX",
	gapstone.X86_REG_ECX:     "REG_ECX",
	gapstone.X86_REG_EDI:     "REG_EDI",
	gapstone.X86_REG_EDX:     "REG_EDX",
	gapstone.X86_REG_EFLAGS:  "REG_EFLAGS",
	gapstone.X86_REG_EIP:     "REG_EIP",
	gapstone.X86_REG_EIZ:     "REG_EIZ",
	gapstone.X86_REG_ES:      "REG_ES",
	gapstone.X86_REG_ESI:     "REG_ESI",
	gapstone.X86_REG_ESP:     "REG_ESP",
	gapstone.X86_REG_FPSW:    "REG_FPSW",
	gapstone.X86_REG_FS:      "REG_FS",
	gapstone.X86_REG_GS:      "REG_GS",
	gapstone.X86_REG_IP:      "REG_IP",
	gapstone.X86_REG_RAX:     "REG_RAX",
	gapstone.X86_REG_RBP:     "REG_RBP",
	gapstone.X86_REG_RBX:     "REG_RBX",
	gapstone.X86_REG_RCX:     "REG_RCX",
}

func GetX86RegName(reg uint) string {
	if name, ok := regNameMap[reg]; ok {
		return name
	}
	return "REG_UNKNOWN"
}
