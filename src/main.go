package main

import (
    elf "backward-slicer/elf"
    logger "backward-slicer/logger"
    "os"
    "path/filepath"
    "strings"
    "github.com/bnagy/gapstone"
)

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

    textSh := target.GetSectionBinByName(".text")
    engine, err := gapstone.New(
        gapstone.CS_ARCH_X86,
        gapstone.CS_MODE_64,
    )
    if err != nil {
        panic("analize binary failed")
    }
    insns, err := engine.Disasm(textSh, 0x00, 0)
    if err != nil {
        panic("Disasm failed")
    }
    for _, insn := range insns {
        if isBranchInsn(insn.Mnemonic) {
            fmt.Println(insn.Mnemonic)
        }
    }

    
    if err == nil {
        log.Printf("Disasm:\n")
        for _, insn := range insns {
            log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
        }
        return
    }	os.Exit(0)
}

func isBranchInsn(mnemonic string) bool {
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
    if nm == "JMP" {
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

/*
func analizeBinary(target elf.ElfObject) {
    textSh := target.GetSectionBinByName(".text")
    engine, err := gapstone.New(
        gapstone.CS_ARCH_X86,
        gapstone.CS_MODE_64,
    )
    if err != nil {
        panic("analize binary failed")
    }
    insns, err := engine.Disasm(textSh, 0x00, 0)
    if err != nil {
        panic("Disasm failed")
    }
    for _, insn := range insns {
        if isBranchInsn(insn.Mnemonic) {
            fmt.Println(insn.Mnemonic)
        }
    }
}
*/
