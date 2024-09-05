# Pe 结构

![image-20240824234852875](/Users/mr.li/Library/Application Support/typora-user-images/image-20240824234852875.png)

### 常用公式

```
RAW = RVA - VirtualAddress + PointerToRawData

理解：

RAW 为文件物理地址

RVA 为内存中虚拟偏移地址

VirtualAddress    为对应区段的内存起始地址

PointerToRawData   为对应区段的文件起始地址
```



### 一、PE.导入表

```
IAT 即导入表

首先需要确定导入表的起始地址

PE --> OptionalHeader --> DataDirectory[1] --> Import Directory  
地址就是在可选头的DataDirectory结构中的第二个，第一个为导出表


⚠️从这里开始 通过 RAW 文件拿到的地址均为RVA （在内存中的相对 Imagebase 的偏移地址，因为文件进入内存会展开）
⚠️所以要通过 RAW 去分析的话，需要我们先把地址转换为 RAW 再通过 HexView / 010Editor 去分析

ImportDirectory --> ImportDirectory.VirtualAddress --> VA to RVA

同时还存在 ImportDirectory.Size，所以可能不光只有一张表，每张表结构如下
```

![image-20240824235349673](/Users/mr.li/Library/Application Support/typora-user-images/image-20240824235349673.png)

```
如果我们要查看名字，则需要将 Name 的地址转为 RAW 然后去寻找
```





接下来以notepad.exe为例

#### 1.ImportDirectory.Name

![image-20240825000952956](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825000952956.png)

![image-20240825001032796](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825001032796.png)

```
OptionalHeader 文件偏移 0x110
DataDirectory  初始偏移 0x180
```

![image-20240825001114712](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825001114712.png)

![image-20240825001229059](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825001229059.png)

```
IMPORT  相对虚拟地址为  0x2FD98

0x2FD98 所属的区段位置为 .rdata

RAW = 0x2FD98 - 0x29000 + 0x27600 = 0x2e398

END = 0x2e398 + 0x3E8 = 0x2e780

从 0x2e398 到 0x2e780 均为导入表

所以我们这里取一个看一下
```

![image-20240825002118466](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825002118466.png)

```
由上图可知

OriginalFirstThunk(INT)   0x000303E0
TimeDateStamp 						0x0
ForwarderChain						0x0
Name											0x00030E2c
First Thunk(IAT)					0x00029060

Name 具体值为

0x30E2c 为 .rdata 段

RAW = 0x30E2c - 0x29000 + 0x27600 = 0x2F42C
```

![image-20240825002800437](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825002800437.png)



#### 2.ImportDirectory.OriginalFirstThunk(INT)

```
OriginalFirstThunk(INT) 计算

RAW = 0x303E0 - 0x29000 + 0x27600 = 0x2E9E0

INT是 一个包含导人函数信息 (Ordinal, Name)的结构体指针数组。只有获得了这些信息， 才能在加载到进程内存的库中准确求得相应函数的起始地址

INT，由地址数 组形式组成(数组尾部以NULL结束)。每个地址值分别指向 IMAGE_IMPORT_BY_NAME 结构体
```

![image-20240825003048627](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825003048627.png)

```
继续跟进地址 0x031166

RAW = 0x31166 - 0x29000 + 0x27600 = 0x2F766

IMAGE_IMPORT_BY_NAME

最初的2个字节值为Ordinal，是库中函数的固有编号 
Ordinal的后面是函数名称字符串
```

![image-20240825003647733](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825003647733.png)



#### 3.FirstThunk - IAT (Import Address Table)

```
First Thunk(IAT)					0x00029060

RAW = 0x29060 - 0x29000 + 0x27600 = 0x27660
```

![image-20240825004645066](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825004645066.png)





### 二、PE.导出表

```
这里以 Kernel32.dll 为例

RAW = RVA - VirtualAddress + PointRaw
```

![image-20240825050942820](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825050942820.png)

![image-20240825051135769](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825051135769.png)

```
由图可知该地址属于 .rdata 区域

RAW = RVA - VirtualAddress + PointerToRawData

0x12AD20 = 0x12c920 - 0xF3000 + 0xF1400
```

<img src="/Users/mr.li/Library/Application Support/typora-user-images/image-20240825010802988.png" alt="image-20240825010802988" style="zoom:50%;" />

![image-20240825010846113](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825010846113.png)

```
找到指定地址的IMAGE_EXPORT_DIRE CTORY结构如下
```

![image-20240825051550446](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825051550446.png)

```
											RVA							RAW
Characteristics  			0x0
TimeDateStamp 				0xFFFFFFFF
MajorVersion    			0x0
MinorVersion    			0x0
Name									0x132436				0x130836
Base									0x1
NumberOfFuctions 			0x67B
NumberONames					0x67B
AddressOfFunctions 		0x12c948					0x12AD48
AdderssOfNames 				0x12FD54					0x12E154
AddressONameOrdinals	0x131740					0x12FB40

从0xE8E6C开始为4字节的节RVA组成的数组

共有 NumberONames	0x67B 个
```

#### 1.AdderssOfNames

![image-20240825052723455](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825052723455.png)

```
跟随第三个地址进去。

0x1324af  RAW 0x1308AF

即可找到函数 ActivateActCtx
```

![image-20240825052838462](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825052838462.png)



#### 2.ordinal

```
AddressONameOrdinals	0x131740					0x12FB40

 由多个2字节的 ordinal 组成的数组
```

![image-20240825052910043](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825052910043.png)

```
因为我们是第三个地址所以这里 ActivateActCtx 对应的值为 0002
```



#### 3.函数地址数组- EAT

```
AddressOfFunctions 		0x12c948				0x12AD48

因为ordinal为2，所以对应的地址如图  RVA = 0x84f50



VA = RVA + ImagebaseAddress

VA = 0x84f50 + 0x80000000 = 0x80084f50
```

![image-20240825052952230](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825052952230.png)

![image-20240825053840362](/Users/mr.li/Library/Application Support/typora-user-images/image-20240825053840362.png)





### 三、PE.重定位表

```
```

