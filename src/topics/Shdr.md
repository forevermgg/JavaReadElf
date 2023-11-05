## Elf64_Shdr
`Elf64_Shdr`是`ELF`（`Executable and Linkable Format`）文件格式中的一个结构体，用于描述`64`位目标文件中的节区（`section`）头部信息。

`ELF`文件是一种常见的二进制文件格式，用于存储可执行文件、共享库和目标文件等。它定义了文件的结构和组织方式，包括头部信息、节区表、程序头部表和节区数据等。

`Elf64_Shdr`结构体定义如下：

```c++
typedef struct {
Elf64_Word      sh_name;        // 节区名称在节区名称表中的索引
Elf64_Word      sh_type;        // 节区类型
Elf64_Xword     sh_flags;       // 节区标志
Elf64_Addr      sh_addr;        // 节区的虚拟地址
Elf64_Off       sh_offset;      // 节区数据在文件中的偏移量
Elf64_Xword     sh_size;        // 节区数据的大小
Elf64_Word      sh_link;        // 链接到的节区的索引
Elf64_Word      sh_info;        // 附加信息
Elf64_Xword     sh_addralign;   // 节区数据的对齐方式
Elf64_Xword     sh_entsize;     // 节区中每个实体的大小
} Elf64_Shdr;
```
其中，各个字段的含义如下：

+ `sh_name`：节区名称在节区名称表中的索引。
+ `sh_type`：节区类型，定义了节区的作用和属性。
+ `sh_flags`：节区标志，描述了节区的属性和权限。
+ `sh_addr`：节区的虚拟地址，用于在内存中定位节区。
+ `sh_offset`：节区数据在文件中的偏移量，用于在文件中定位节区。
+ `sh_size`：节区数据的大小。
+ `sh_link`：链接到的节区的索引，用于建立节区之间的关联。
+ `sh_info`：附加信息，具体含义取决于节区类型。
+ `sh_addralign`：节区数据的对齐方式，通常是`2`的幂次方。
+ `sh_entsize`：节区中每个实体的大小，通常用于描述符号表等节区。

`Elf64_Shdr`结构体中的字段提供了对节区的描述和定位信息，有助于解析和操作`ELF`文件中的节区数据。

### sh_name;        // 节区名称在节区名称表中的索引
### sh_type;        // 节区类型
### sh_flags;       // 节区标志
### sh_addr;        // 节区的虚拟地址
### sh_offset;      // 节区数据在文件中的偏移量
### sh_size;        // 节区数据的大小
### sh_link;        // 链接到的节区的索引
### sh_info;        // 附加信息
### sh_addralign;   // 节区数据的对齐方式
### sh_entsize;     // 节区中每个实体的大小