package main

import (
	"backward-slicer/arch"
	elf "backward-slicer/elf"
	logger "backward-slicer/logger"
	"os"
	"path/filepath"
	"strings"

	"github.com/knightsc/gapstone"
)

const (
	SLICING_STATUS_NONE = iota
	SLICING_STATUS_WAIT_CMP
	SLICING_STATUS_SLICING
)

type CmpConstraint struct {
	operand gapstone.X86Operand
	// 0: ==, 1: !=, 2: <, 3: <=, 4: >, 5: >=
	compareType int
}

type CompareInfo struct {
	cmpInsn      gapstone.Instruction
	targetSlices []gapstone.Instruction
	constraint   CmpConstraint
}

type BasicBlock struct {
	branchInsn gapstone.Instruction
	cmp        CompareInfo
}

func main() {
	logger.Setup(logger.TRACE, false)
	if len(os.Args) < 2 {
		os.Exit(-1)
	}

	targetPath, err := filepath.Abs(os.Args[1])
	if err != nil {
		logger.ShowErrorMsg("%s\n", err.Error())
		os.Exit(-1)
	}

	// check target module is exist
	fi, err := os.Stat(targetPath)
	if err != nil {
		logger.ShowErrorMsg("%s cannot open\n", targetPath)
		os.Exit(-1)
	}

	// check target module is ELF Object
	if !elf.IsELFFile(targetPath) {
		logger.ShowErrorMsg("%s is not ELF Object File\n", targetPath)
		os.Exit(-1)
	}

	f, err := os.Open(targetPath)
	if err != nil {
		logger.ShowErrorMsg("%s cannot open", targetPath)
		os.Exit(-1)
	}
	defer f.Close()

	bin := make([]byte, fi.Size())
	f.Read(bin)

	var targetObj elf.ElfObject
	if elf.IsELF32(bin) {
		targetObj = elf.NewElf32(targetPath, bin)
	} else if elf.IsELF64(bin) {
		targetObj = elf.NewElf64(targetPath, bin)
	}
	machineArch := targetObj.GetMachineArch()
	println("Machine Arch: ", machineArch)

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_32,
	)
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)
	if err != nil {
		panic("failed to create engine")
	}

	logger.DLog("Disasm: %s\n", targetPath)
	textSh := targetObj.GetSectionBinByName(".text")
	insns, err := engine.Disasm(textSh, 0x00, 0)
	if err != nil {
		panic("Disasm failed")
	}
	// reverse insns
	length := len(insns)
	for i := 0; i < length/2; i++ {
		insns[i], insns[length-i-1] = insns[length-i-1], insns[i]
	}

	basicBlock := new(BasicBlock)
	slicingStatus := SLICING_STATUS_NONE
	for _, insn := range insns {
		logger.DLog("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		switch slicingStatus {
		case SLICING_STATUS_NONE:
			if isBranch(insn.Mnemonic) {
				logger.DLog("Branch: %s\n", insn.Mnemonic)
				basicBlock.branchInsn = insn
				slicingStatus = SLICING_STATUS_WAIT_CMP
			}
		case SLICING_STATUS_WAIT_CMP:
			constraint := 0
			if isFlagEffectiveInsn(insn.Mnemonic) {
				for _, operand := range insn.X86.Operands {
					if operand.Type == gapstone.X86_OP_REG {
						logger.DLog("operand1 reg: %s\n", arch.GetX86RegName(operand.Reg))
					}
					if operand.Type == gapstone.X86_OP_MEM {
						reg := operand.Mem.Base
						disp := operand.Mem.Disp
						logger.DLog("operand1 mem: %s %d\n", arch.GetX86RegName(reg), disp)
					}
				}
				slicingStatus = SLICING_STATUS_SLICING
				basicBlock.cmp = CompareInfo{cmpInsn: insn, targetSlices: make([]gapstone.Instruction, 0), constraint: CmpConstraint{operand: insn.X86.Operands[1], compareType: constraint}}
			}
		case SLICING_STATUS_SLICING:
			// cmp 命令に使われているオペランドと同じメモリ、レジスタが更新されている命令をスライス
			for _, operand := range insn.X86.Operands {
				if operand.Access&gapstone.CS_AC_WRITE == 0 {
					logger.DLog("operand is not write")
					continue
				}
				for i, cmpInsnOperand := range basicBlock.cmp.cmpInsn.X86.Operands {
					if cmpInsnOperand.Type == operand.Type {
						if cmpInsnOperand.Type == gapstone.X86_OP_REG {
							if cmpInsnOperand.Reg == operand.Reg {
								logger.DLog("same as cmpOpperand[%d] reg: %s is updated", i, arch.GetX86RegName(operand.Reg))
								basicBlock.cmp.targetSlices = append(basicBlock.cmp.targetSlices, insn)
							}
						} else if cmpInsnOperand.Type == gapstone.X86_OP_MEM {
							if cmpInsnOperand.Mem.Base == operand.Mem.Base && cmpInsnOperand.Mem.Disp == operand.Mem.Disp {
								logger.DLog("same as cmpOpperand[%d] mem: %s %d is updated", i, arch.GetX86RegName(operand.Mem.Base), operand.Mem.Disp)
								basicBlock.cmp.targetSlices = append(basicBlock.cmp.targetSlices, insn)
							}
						}
					}
				}
			}
		}
	}

	// ここで原因となる命令の情報を表示
	operand := basicBlock.cmp.constraint.operand
	if operand.Type == gapstone.X86_OP_IMM {
		value := operand.Imm
		lastIdx := len(basicBlock.cmp.targetSlices)
		causeInsn := basicBlock.cmp.targetSlices[lastIdx-1]
		if causeInsn.X86.Operands[1].Type == gapstone.X86_OP_REG {
			regName := arch.GetX86RegName(causeInsn.X86.Operands[1].Reg)
			logger.DLog("%s must be %d\n", regName, value)
		}
	}

	os.Exit(0)
}

func isFlagEffectiveInsn(mnemonic string) bool {
	nm := strings.ToUpper(mnemonic)
	return nm == "CMP"
}

func isBranch(mnemonic string) bool {
	// not implemented
	// JO,JNO
	// JS,JNS
	// JB,JNAE,JC
	// JNB,JAE,JNC
	// JBE,JNA
	// JA,JNBE

	// implemented
	// call
	// JMP,JE,JZ,JNE,JNZ,JL,JNGE,JGE,JNL,JLE,JNG,JG,JNLE
	nm := strings.ToUpper(mnemonic)
	if nm == "CALL" {
		return true
	}
	if nm == "JE" {
		return true
	}
	if nm == "JZ" {
		return true
	}
	if nm == "JNE" {
		return true
	}
	if nm == "JNZ" {
		return true
	}
	if nm == "JL" {
		return true
	}
	if nm == "JNGE" {
		return true
	}
	if nm == "JGE" {
		return true
	}
	if nm == "JNL" {
		return true
	}
	if nm == "JLE" {
		return true
	}
	if nm == "JNG" {
		return true
	}
	if nm == "JG" {
		return true
	}
	if nm == "JNLE" {
		return true
	}
	return false
}
