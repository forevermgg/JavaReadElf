/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.Map;

/**
 * A poor man's implementation of the readelf command. This program is designed
 * to parse ELF (Executable and Linkable Format) files.
 */
public class ReadElf implements AutoCloseable {
    /** The magic values for the ELF identification. */
    private static final byte[] ELFMAG = {
            (byte) 0x7F, (byte) 'E', (byte) 'L', (byte) 'F', };

    private static final int EI_NIDENT = 16;

    private static final int EI_CLASS = 4;
    private static final int EI_DATA = 5;

    private static final int EM_386 = 3;
    private static final int EM_ARM = 40;
    private static final int EM_X86_64 = 62;
    // http://en.wikipedia.org/wiki/Qualcomm_Hexagon
    private static final int EM_QDSP6 = 164;
    private static final int EM_AARCH64 = 183;
    private static final int EM_RISCV = 243;

    private static final int ELFCLASS32 = 1;
    private static final int ELFCLASS64 = 2;

    private static final int ELFDATA2LSB = 1;
    private static final int ELFDATA2MSB = 2;

    private static final int EV_CURRENT = 1;

    private static final long PT_LOAD = 1;

    private static final int SHT_SYMTAB = 2;
    private static final int SHT_STRTAB = 3;
    private static final int SHT_DYNAMIC = 6;
    private static final int SHT_DYNSYM = 11;

    public static class Symbol {
        public static final int STB_LOCAL = 0;
        public static final int STB_GLOBAL = 1;
        public static final int STB_WEAK = 2;
        public static final int STB_LOPROC = 13;
        public static final int STB_HIPROC = 15;

        public static final int STT_NOTYPE = 0;
        public static final int STT_OBJECT = 1;
        public static final int STT_FUNC = 2;
        public static final int STT_SECTION = 3;
        public static final int STT_FILE = 4;
        public static final int STT_COMMON = 5;
        public static final int STT_TLS = 6;

        public final String name;
        public final int bind;
        public final int type;

        Symbol(String name, int st_info) {
            this.name = name;
            this.bind = (st_info >> 4) & 0x0F;
            this.type = st_info & 0x0F;
        }

        @Override
        public String toString() {
            return "Symbol[" + name + "," + toBind() + "," + toType() + "]";
        }

        private String toBind() {
            switch (bind) {
                case STB_LOCAL:
                    return "LOCAL";
                case STB_GLOBAL:
                    return "GLOBAL";
                case STB_WEAK:
                    return "WEAK";
            }
            return "STB_??? (" + bind + ")";
        }

        private String toType() {
            switch (type) {
                case STT_NOTYPE:
                    return "NOTYPE";
                case STT_OBJECT:
                    return "OBJECT";
                case STT_FUNC:
                    return "FUNC";
                case STT_SECTION:
                    return "SECTION";
                case STT_FILE:
                    return "FILE";
                case STT_COMMON:
                    return "COMMON";
                case STT_TLS:
                    return "TLS";
            }
            return "STT_??? (" + type + ")";
        }
    }

    private final String mPath;
    private final RandomAccessFile mFile;
    private final byte[] mBuffer = new byte[512];
    private int mEndian;
    private boolean mIsDynamic;
    private boolean mIsPIE;
    private int mType;
    private int mAddrSize;

    /** Symbol Table offset */
    private long mSymTabOffset;

    /** Symbol Table size */
    private long mSymTabSize;

    /** Dynamic Symbol Table offset */
    private long mDynSymOffset;

    /** Dynamic Symbol Table size */
    private long mDynSymSize;

    /** Section Header String Table offset */
    private long mShStrTabOffset;

    /** Section Header String Table size */
    private long mShStrTabSize;

    /** String Table offset */
    private long mStrTabOffset;

    /** String Table size */
    private long mStrTabSize;

    /** Dynamic String Table offset */
    private long mDynStrOffset;

    /** Dynamic String Table size */
    private long mDynStrSize;

    /** Symbol Table symbol names */
    private Map<String, Symbol> mSymbols;

    /** Dynamic Symbol Table symbol names */
    private Map<String, Symbol> mDynamicSymbols;

    public static ReadElf read(File file) throws IOException {
        return new ReadElf(file);
    }

    public static void main(String[] args) throws IOException {
        for (String arg : args) {
            ReadElf re = new ReadElf(new File(arg));
            re.getSymbol("x");
            re.getDynamicSymbol("x");
            re.close();
        }
    }

    public boolean isDynamic() {
        return mIsDynamic;
    }

    public int getType() {
        return mType;
    }

    public boolean isPIE() {
        return mIsPIE;
    }

    public ReadElf(File file) throws IOException {
        mPath = file.getPath();
        mFile = new RandomAccessFile(file, "r");

        if (mFile.length() < EI_NIDENT) {
            throw new IllegalArgumentException("Too small to be an ELF file: " + file);
        }

        readHeader();
    }

    @Override
    public void close() {
        try {
            mFile.close();
        } catch (IOException ignored) {
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    private void readHeader() throws IOException {
        mFile.seek(0);
        // 0~EI_NIDENT 为有效数据，其余数据皆为0；
        mFile.readFully(mBuffer, 0, EI_NIDENT);
        /*关于标识符e_ident 16个字节的值含义：
        名称 位置 说明
        EI_MAG0 0 文件标识(0x7f)
        EI_MAG1 1 文件标识(E)
        EI_MAG2 2 文件标识(L)
        EI_MAG3 3 文件标识(F)
        EI_CLASS 4 文件类，取值：0-非法，1-32位，2-64位
        EI_DATA 5 数据编码，取值：0-非法，1-小端，2-大端
        EI_VERSION 6 ELF头部版本
        EI_PAD 7~15 补齐字节，一般为0*/
        System.err.println("ReadElf" + " Buffer EI_NIDENT = " + bytes2hex(mBuffer));
        if (mBuffer[0] != ELFMAG[0] || mBuffer[1] != ELFMAG[1] ||
                mBuffer[2] != ELFMAG[2] || mBuffer[3] != ELFMAG[3]) {
            throw new IllegalArgumentException("Invalid ELF file: " + mPath);
        }

        int elfClass = mBuffer[EI_CLASS]; // EI_CLASS == 4
        System.err.println("ReadElf" + " EI_CLASS = " + bytes2hex(new byte[]{(byte) elfClass}));
        if (elfClass == ELFCLASS32) {
            mAddrSize = 4;
        } else if (elfClass == ELFCLASS64) {
            mAddrSize = 8;
        } else {
            throw new IOException("Invalid ELF EI_CLASS: " + elfClass + ": " + mPath);
        }

        mEndian = mBuffer[EI_DATA]; // EI_CLASS == 5
        System.err.println("ReadElf" + " EI_DATA = " + bytes2hex(new byte[]{(byte) mEndian}));
        if (mEndian == ELFDATA2LSB) {
            System.err.println("ReadElf" + " EI_DATA = " + bytes2hex(new byte[]{(byte) mEndian}));
        } else if (mEndian == ELFDATA2MSB) {
            throw new IOException("Unsupported ELFDATA2MSB file: " + mPath);
        } else {
            throw new IOException("Invalid ELF EI_DATA: " + mEndian + ": " + mPath);
        }

        /*关于文件类型e_type取值：
        0 NONE (未知目标文件格式)
        1 REL (可重定位文件)
        2 EXEC (可执行文件)
        3 DYN (共享目标文件)
        4 CORE (转储格式)*/
        // Elf64_Half 2    2         Unsigned medium integer
        // Elf64_Half e_type; /* Object file type */
        mType = readHalf();
        System.err.println("ReadElf" + " mType = " + mType);
        /*关于体系架构e_machine取值：
        0 No machine
        2 SPARC
        3 Intel 80386
        8 MIPS I Architecture
        0x14 PowerPC
        0x28 Advanced RISC Machines ARM
        0x3e Advanced Micro Devices X86-64*/
        // Name       Size Alignment Purpose
        // Elf64_Half 2    2         Unsigned medium integer
        // Elf64_Half e_machine; /* Machine type */
        // e_machine 标识目标架构
        int e_machine = readHalf();
        System.err.println("ReadElf" + " e_machine = " + e_machine);
        if (e_machine != EM_386 && e_machine != EM_X86_64 &&
                e_machine != EM_AARCH64 && e_machine != EM_ARM &&
                e_machine != EM_RISCV && e_machine != EM_QDSP6) {
            throw new IOException("Invalid ELF e_machine: " + e_machine + ": " + mPath);
        }

        // AbiTest relies on us rejecting any unsupported combinations.
        if ((e_machine == EM_386 && elfClass != ELFCLASS32) ||
                (e_machine == EM_AARCH64 && elfClass != ELFCLASS64) ||
                (e_machine == EM_ARM && elfClass != ELFCLASS32) ||
                (e_machine == EM_QDSP6 && elfClass != ELFCLASS32) ||
                (e_machine == EM_RISCV && elfClass != ELFCLASS64) ||
                (e_machine == EM_X86_64 && elfClass != ELFCLASS64)) {
            throw new IOException("Invalid e_machine/EI_CLASS ELF combination: " +
                    e_machine + "/" + elfClass + ": " + mPath);
        }

        // Name       Size Alignment   Purpos
        // Elf64_Word 4    4           Unsigned integer
        // Elf64_Word e_version; /* Object file version */
        // e_version 文件格式的版本
        long e_version = readWord();
        if (e_version != EV_CURRENT) {
            throw new IOException("Invalid e_version: " + e_version + ": " + mPath);
        }

        // Elf64_Addr 8 8 Unsigned program address
        // Elf64_Addr e_entry; /* Entry point address */
        // e_entry 程序入口的虚拟地址
        long e_entry = readAddr();
        System.err.println("ReadElf" + " e_entry = " + e_entry);
        // Elf64_Off 8 8 Unsigned file offset
        // Elf64_Off e_phoff; /* Program header offset */
        // e_phoff 程序段头表在该文件内的偏移，单位是字节
        long ph_off = readOff();
        System.err.println("ReadElf" + " ph_off = " + ph_off);
        // Elf64_Off 8 8 Unsigned file offset
        // Elf64_Off e_shoff; /* Section header offset */
        // e_shoff 节头表在该文件内的偏移，单位是字节
        long sh_off = readOff();

        // Elf64_Word 4 4 Unsigned integer
        // Elf64_Word e_flags; /* Processor-specific flags *
        // e_flags 包含处理器特定的标记
        long e_flags = readWord();

        // Elf64_Half 2 2 Unsigned medium integer
        // Elf64_Half e_ehsize; /* ELF header size */
        // e_ehsize ELF头的大小，单位是字节
        int e_ehsize = readHalf();

        // Elf64_Half 2 2 Unsigned medium integer
        // Elf64_Half e_phentsize; /* Size of program header entry */
        // e_phentsize 程序段头表项的大小，单位是字节
        int e_phentsize = readHalf();

        // Elf64_Half 2 2 Unsigned medium integer
        // Elf64_Half e_phnum; /* Number of program header entries */
        // e_phnum 程序段头表项的数量
        int e_phnum = readHalf();

        // Elf64_Half 2 2 Unsigned medium integer
        // Elf64_Half e_shentsize; /* Size of section header entry */
        // e_shentsize 节头表项的大小，单位是字节
        int e_shentsize = readHalf();


        // Elf64_Half 2 2 Unsigned medium integer
        // Elf64_Half e_shnum; /* Number of section header entries */
        // e_shnum 节头表项的数量
        int e_shnum = readHalf();


        // Elf64_Half 2 2 Unsigned medium integer
        // Elf64_Half e_shstrndx; /* Section name string table index */
        // e_shstrndx 节头表中包含节名字的字符串表索引。
        int e_shstrndx = readHalf();
        System.err.println("ReadElf" + " e_shstrndx = " + e_shstrndx);
        readSectionHeaders(sh_off, e_shnum, e_shentsize, e_shstrndx);
        readProgramHeaders(ph_off, e_phnum, e_phentsize);
    }

    private void readSectionHeaders(long sh_off, int e_shnum, int e_shentsize, int e_shstrndx)
            throws IOException {
        // Read the Section Header String Table offset first.
        {
            mFile.seek(sh_off + e_shstrndx * e_shentsize);
            // Elf64_Word sh_name; /* Section name *
            // sh_name 节头名字在字符串表中的偏移，单位是字节。
            long sh_name = readWord();
            System.err.println("ReadElf" + " all sh_name = " + readShStrTabEntry(sh_name));
            // Elf64_Word sh_type; /* Section type */
            // sh_type 节的类型
            long sh_type = readWord();
            // Elf64_Xword sh_flags; /* Section attributes */
            // sh_flags 当前节的属性
            long sh_flags = readX(mAddrSize);
            // Elf64_Addr sh_addr; /* Virtual address in memory */
            // sh_addr 该节在内存中的虚拟地址，如果不加载到内存中，地址是0
            long sh_addr = readAddr();
            // Elf64_Off sh_offset; /* Offset in file */
            // sh_offset 该节在文件中的偏移，单位是字节
            long sh_offset = readOff();
            // Elf64_Xword sh_size; /* Size of section */
            // sh_size 当前节在文件中占用的空间，唯一的例外是SHT_NOBITS，不占用文件空间
            long sh_size = readX(mAddrSize);
            // ...
            // Elf64_Word sh_link; /* Link to other section */
            // Elf64_Word sh_info; /* Miscellaneous information */
            // Elf64_Xword sh_addralign; /* Address alignment boundary */
            // Elf64_Xword sh_entsize; /* Size of entries, if section has table *
            if (sh_type == SHT_STRTAB) {
                mShStrTabOffset = sh_offset;
                mShStrTabSize = sh_size;
            }
        }

        for (int i = 0; i < e_shnum; ++i) {
            // Don't bother to re-read the Section Header StrTab.
            if (i == e_shstrndx) {
                continue;
            }

            mFile.seek(sh_off + i * e_shentsize);

            long sh_name = readWord();
            System.err.println("ReadElf" + " sh_name = " + readShStrTabEntry(sh_name));
            long sh_type = readWord();
            long sh_flags = readX(mAddrSize);
            long sh_addr = readAddr();
            long sh_offset = readOff();
            long sh_size = readX(mAddrSize);

            if (sh_type == SHT_SYMTAB || sh_type == SHT_DYNSYM) {
                final String symTabName = readShStrTabEntry(sh_name);
                if (".symtab".equals(symTabName)) {
                    mSymTabOffset = sh_offset;
                    mSymTabSize = sh_size;
                } else if (".dynsym".equals(symTabName)) {
                    mDynSymOffset = sh_offset;
                    mDynSymSize = sh_size;
                }
            } else if (sh_type == SHT_STRTAB) {
                final String strTabName = readShStrTabEntry(sh_name);
                if (".strtab".equals(strTabName)) {
                    mStrTabOffset = sh_offset;
                    mStrTabSize = sh_size;
                } else if (".dynstr".equals(strTabName)) {
                    mDynStrOffset = sh_offset;
                    mDynStrSize = sh_size;
                }
            } else if (sh_type == SHT_DYNAMIC) {
                mIsDynamic = true;
            }
        }
    }

    private void readProgramHeaders(long ph_off, int e_phnum, int e_phentsize) throws IOException {
        for (int i = 0; i < e_phnum; ++i) {
            mFile.seek(ph_off + i * e_phentsize);

            long p_type = readWord();
            if (p_type == PT_LOAD) {
                if (mAddrSize == 8) {
                    // Only in Elf64_phdr; in Elf32_phdr p_flags is at the end.
                    long p_flags = readWord();
                }
                long p_offset = readOff();
                long p_vaddr = readAddr();
                // ...

                if (p_vaddr == 0) {
                    mIsPIE = true;
                }
            }
        }
    }

    private HashMap<String, Symbol> readSymbolTable(long symStrOffset, long symStrSize,
                                                    long tableOffset, long tableSize) throws IOException {
        HashMap<String, Symbol> result = new HashMap<String, Symbol>();
        mFile.seek(tableOffset);
        while (mFile.getFilePointer() < tableOffset + tableSize) {
            long st_name = readWord();
            int st_info;
            if (mAddrSize == 8) {
                st_info = readByte();
                int st_other = readByte();
                int st_shndx = readHalf();
                long st_value = readAddr();
                long st_size = readX(mAddrSize);
            } else {
                long st_value = readAddr();
                long st_size = readWord();
                st_info = readByte();
                int st_other = readByte();
                int st_shndx = readHalf();
            }
            if (st_name == 0) {
                continue;
            }

            final String symName = readStrTabEntry(symStrOffset, symStrSize, st_name);
            if (symName != null) {
                System.err.println("ReadElf readSymbolTable " + " symName = " + symName);
                Symbol s = new Symbol(symName, st_info);
                result.put(symName, s);
            }
        }
        return result;
    }

    private String readShStrTabEntry(long strOffset) throws IOException {
        if (mShStrTabOffset == 0 || strOffset < 0 || strOffset >= mShStrTabSize) {
            return null;
        }
        return readString(mShStrTabOffset + strOffset);
    }

    private String readStrTabEntry(long tableOffset, long tableSize, long strOffset)
            throws IOException {
        if (tableOffset == 0 || strOffset < 0 || strOffset >= tableSize) {
            return null;
        }
        return readString(tableOffset + strOffset);
    }

    private int readHalf() throws IOException {
        return (int) readX(2);
    }

    private long readWord() throws IOException {
        return readX(4);
    }

    private long readOff() throws IOException {
        return readX(mAddrSize);
    }

    private long readAddr() throws IOException {
        return readX(mAddrSize);
    }

    private long readX(int byteCount) throws IOException {
        mFile.readFully(mBuffer, 0, byteCount);
        // System.err.println("ReadElf" + " readX = " + bytes2hex(mBuffer));
        int answer = 0;
        if (mEndian == ELFDATA2LSB) {
            for (int i = byteCount - 1; i >= 0; i--) {
                answer = (answer << 8) | (mBuffer[i] & 0xff);
            }
        } else {
            final int N = byteCount - 1;
            for (int i = 0; i <= N; ++i) {
                answer = (answer << 8) | (mBuffer[i] & 0xff);
            }
        }

        return answer;
    }

    private String readString(long offset) throws IOException {
        long originalOffset = mFile.getFilePointer();
        mFile.seek(offset);
        mFile.readFully(mBuffer, 0, (int) Math.min(mBuffer.length, mFile.length() - offset));
        mFile.seek(originalOffset);

        for (int i = 0; i < mBuffer.length; ++i) {
            if (mBuffer[i] == 0) {
                return new String(mBuffer, 0, i);
            }
        }

        return null;
    }

    private int readByte() throws IOException {
        return mFile.read() & 0xff;
    }

    public Symbol getSymbol(String name) {
        if (mSymbols == null) {
            try {
                mSymbols = readSymbolTable(mStrTabOffset, mStrTabSize, mSymTabOffset, mSymTabSize);
            } catch (IOException e) {
                return null;
            }
        }
        return mSymbols.get(name);
    }

    public Symbol getDynamicSymbol(String name) {
        if (mDynamicSymbols == null) {
            try {
                mDynamicSymbols = readSymbolTable(
                        mDynStrOffset, mDynStrSize, mDynSymOffset, mDynSymSize);
            } catch (IOException e) {
                return null;
            }
        }
        return mDynamicSymbols.get(name);
    }

    public static String bytes2hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        String tmp;
        sb.append("[").append("\n");
        int count = 0;
        for (byte b : bytes) {
            // 将每个字节与0xFF进行与运算，然后转化为10进制，然后借助于Integer再转化为16进制
            tmp = Integer.toHexString(0xFF & b);
            if (tmp.length() == 1) {
                tmp = "0" + tmp;//只有一位的前面补个0
            }
            if (count == 16) {
                count = 1;
                sb.append("\n");
            } else {
                count ++;
            }
            sb.append(tmp).append(" ");//每个字节用空格断开
        }
        // sb.delete(sb.length() - 1, sb.length());//删除最后一个字节后面对于的空格
        sb.append("\n").append("]");
        return sb.toString();
    }
}