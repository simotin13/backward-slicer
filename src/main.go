package main

import (
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

type BranchSlice struct {
    branchInsn gapstone.Instruction
    cmpInsn gapstone.Instruction
    slices []gapstone.Instruction
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
    for i := 0; i < length / 2; i++ {
        insns[i], insns[length - i - 1] = insns[length - i - 1], insns[i]
    }

    branchSlice := new(BranchSlice)
    slicingStatus := SLICING_STATUS_NONE
    for _, insn := range insns {
        logger.DLog("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
        switch slicingStatus {
        case SLICING_STATUS_NONE:
            if isBranch(insn.Mnemonic) {
                logger.DLog("Branch: %s\n", insn.Mnemonic)
                branchSlice.branchInsn = insn
                slicingStatus = SLICING_STATUS_WAIT_CMP
            }
        case SLICING_STATUS_WAIT_CMP:
            if isFlagEffectiveInsn(insn.Mnemonic) {
                logger.DLog("Flag Effective: %s\n", insn.Mnemonic)
                slicingStatus = SLICING_STATUS_SLICING
                branchSlice.cmpInsn = insn
            }
        case SLICING_STATUS_SLICING:
            // 
        }
    }
    os.Exit(0)
}

func isFlagEffectiveInsn(mnemonic string) bool {
    nm := strings.ToUpper(mnemonic)
    if nm == "CMP" {
        return true
    }
    return false
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
