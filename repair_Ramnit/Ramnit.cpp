#include "Ramnit.h"
#include <iostream>
#include <Windows.h>
#include <Shlwapi.h>

HANDLE hFile;
HANDLE hMap;
HANDLE hFileMapAddr;
WORD numOfSection;
DWORD sizeOfImage;
DWORD OEP;

IMAGE_DOS_HEADER* dosHeader;
IMAGE_NT_HEADERS* ntHeader;
IMAGE_FILE_HEADER* fileHeader;
IMAGE_OPTIONAL_HEADER* optionalHeader;
IMAGE_SECTION_HEADER* sectionHeader;

int JudgeFileType(char path[MAX_PATH]);
int ExcludeFile(char* string);
void CloseAllHandle();

//映射目标文件
DWORD MapFile(char filename[MAX_PATH])
{
	//映射文件到内存中
	hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile)
	{
		hMap = CreateFileMappingA(hFile, 0, PAGE_READWRITE, 0, 0, 0);
		if (hMap)
		{
			hFileMapAddr = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
			dosHeader = (PIMAGE_DOS_HEADER)hFileMapAddr;
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				CloseAllHandle();
				return 0;
			}
			ntHeader = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (PBYTE)dosHeader);
			if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				CloseAllHandle();
				return 0;
			}
			fileHeader = (PIMAGE_FILE_HEADER) & (ntHeader->FileHeader);
			optionalHeader = (PIMAGE_OPTIONAL_HEADER) & (ntHeader->OptionalHeader);
			numOfSection = fileHeader->NumberOfSections;
			sizeOfImage = optionalHeader->SizeOfImage;
			//sizeOfHeader = optionalHeader->SizeOfHeaders;
			sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
			return 1;
		}
		else
		{
			CloseHandle(hFile);
			return 0;
		}
	}
	else
	{
		return 0;
	}
}
//排除. ..和RMNetwork
int ExcludeFile(char* string)
{
	return !lstrcmpA(string, ".") || !lstrcmpA(string, "..") || !lstrcmpA(string, "RMNetwork");
}

//判断是否是system或windows目录
int JudgeFilePath(char* string)
{
	if (!lstrcmpA(string, "C:\\Windows\\") || !lstrcmpA(string, "C:\\Windows\System32\\"))
		return 1;
	return 0;
}

//判断文件类型
int JudgeFileType(char path[MAX_PATH])
{
	LPCSTR suffix = PathFindExtensionA(path);
	if (!lstrcmpA(suffix, ".exe") || !lstrcmpA(suffix, ".dll"))
	{
		return 0;			//返回0，表示当前文件为exe文件或是dll文件
	}
	else if (!lstrcmpA(suffix, ".htm") || !lstrcmpA(suffix, ".html"))
	{
		return 1;			//返回1，标表示当前文件为htm或html
	}
	else
		return 2;
}

//修复html1
void repairHtml1(char filepath[MAX_PATH])
{
	char Buffer[20];
	HANDLE hfile;
	DWORD NumberOfBytesRead;
	SetFileAttributesA(filepath, FILE_ATTRIBUTE_NORMAL);
	hfile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile != INVALID_HANDLE_VALUE)
	{
		DWORD filesize = GetFileSize(hfile, 0);
		if (filesize != -1)
		{
			printf("----------------------------------------------------------------------------------------\n");
			printf("|%s文件\n", filepath);
			printf("|开始修复文件！\n");
			SetFilePointer(hfile, filesize - 280034, 0, FILE_BEGIN);				
			SetEndOfFile(hfile);
			CloseHandle(hfile);
			printf("|修复完成!\n");
			printf("-----------------------------------------------------------------------------------------\n");
			printf("\n");
		}
	}
	else
		CloseHandle(hfile);
}

//修复html2
void repairHtml2(char filepath[MAX_PATH])
{
	char Buffer[600];
	HANDLE hfile;
	DWORD NumberOfBytesRead;
	SetFileAttributesA(filepath, FILE_ATTRIBUTE_NORMAL);
	hfile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile != INVALID_HANDLE_VALUE)
	{
		DWORD filesize = GetFileSize(hfile, 0);
		if (filesize != -1)
		{
			printf("----------------------------------------------------------------------------------------\n");
			printf("|%s文件\n", filepath);
			printf("|开始修复文件！\n");
			SetFilePointer(hfile, filesize - 539, 0, 0);				//539为附加随机数据的最大长度
			ReadFile(hfile, Buffer, 539, &NumberOfBytesRead, 0);	//读取文件末尾539字节的数据到buffer中
			const char strcharacteristic[20] = "</SCRIPT><!--";
			char* ret = strstr(Buffer, strcharacteristic);
			DWORD Distance = filesize - (262630 + (539 - (ret - Buffer) - 13));
			printf("|原始文件大小为：%d\n",Distance);
			SetFilePointer(hfile, Distance, 0, FILE_BEGIN);
			SetEndOfFile(hfile);
			CloseHandle(hfile);
			printf("|修复完成!\n");
			printf("-----------------------------------------------------------------------------------------\n");
			printf("\n");

		}
	}
	else
		CloseHandle(hfile);
}

//关闭句柄
void CloseAllHandle()
{
	UnmapViewOfFile(hFileMapAddr);
	CloseHandle(hMap);
	CloseHandle(hFile);
}

//判断.rmnet节表是否存在 
//返回1，说明rmnet节存在
//返回0，说明rmnet节不存在
BOOL JudgeSection()
{
	char* sectionName = (char*)sectionHeader[numOfSection - 1].Name;
	if (strcmp(sectionName, ".rmnet") == 0)
	{
		return 1;//返回1，说明rmnet节表存在
	}
	return 0;//返回0，说明节表不存在
}

//判断文件末尾的感染特征  返回true，说明该文件被感染
//flag = 0 为PE判断
//flag = 3 为网页判断
BOOL JudgeCharacteristic(char filename[MAX_PATH], int flag)
{
	DWORD Buffer[30];
	HANDLE hfile;
	DWORD NumberOfBytesRead;
	DWORD FileSizeHigh;
	DWORD characteristic = 0xFA1BC352;
	hfile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, 3u, 0x80u, 0);
	if (hfile != INVALID_HANDLE_VALUE)
	{
		DWORD filesize = GetFileSize(hfile, &FileSizeHigh);
		if (filesize > flag + 24 && filesize != -1 && !FileSizeHigh)
		{
			SetFilePointer(hfile, filesize - (flag + 0x24), 0, 0);
			ReadFile(hfile, Buffer, 0x24, &NumberOfBytesRead, 0);
			CloseHandle(hfile);
			int j = 9;
			for (DWORD i = Buffer[0];; Buffer[j] ^= i)
			{
				--j;
				if (!(j * 4))
					break;
			}
			if (Buffer[1] == characteristic && Buffer[2] == 5 && Buffer[3] == 0 && Buffer[4] == 0x0D)
				return true;	//返回true，说明该文件被感染
			else
				return false;	//返回false，说明该文件没有被感染，或是不属于该文件类型
		}
		else
		{
			printf("打开文件失败！");
			CloseHandle(hfile);
			return false;		//文件大小不满足条件，没有被感染
		}

	}
	else
		return false;		//文件打开失败
}

//删除多余节表
void FixSection()
{
	//删除多余节表数据
	optionalHeader->SizeOfImage -= sectionHeader[numOfSection - 1].Misc.VirtualSize;  //修正sizeofimage  
	memset(sectionHeader[numOfSection - 1].PointerToRawData + (PBYTE)dosHeader, 0, sectionHeader[numOfSection - 1].SizeOfRawData);

	//修正DOS头								
	fileHeader->NumberOfSections--;	//节表个数-1
	memset(&sectionHeader[numOfSection - 1], 0, 0x28);	//将最后一个节的数据全置0
	printf("|成功修复多余节表！\n");
}


Ramnit::Ramnit()
{
	this->fileType = 2 ;		//不是感染文件
	this->RamnitType = 3;		//文件没有被感染
}

//遍历
void Ramnit::Traverserepair()
{
	char szBuffer[MAX_PATH];
	DWORD result = GetLogicalDriveStringsA(MAX_PATH, szBuffer);
	for (char* i = szBuffer; *i; i += 4)
	{
		unsigned int type = GetDriveTypeA(i);
		if ( type == DRIVE_FIXED )
		{
			printf("*************************************\n");
			printf("*************************************\n");
			printf("	开始修复磁盘：%s\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
			TraverseAllFile(i);
			printf("*************************************\n");
			printf("*************************************\n");
			printf("	磁盘%s已修复完成\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
		}
		else if ( type == DRIVE_REMOVABLE )
		{
			printf("*************************************\n");
			printf("*************************************\n");
			printf("	开始修复可移动磁盘 ：%s\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
			//FixRemovAble(i);
			printf("*************************************\n");
			printf("*************************************\n");
			printf("	磁盘%s已修复完成\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
		}
	}
}

//判断感染类型，返回1，说明感染类型为Ramnit.x或Ramnit.AS
//返回0，打开文件失败
//返回1，说明感染类型为Ramnit.x或Ramnit.AS
//返回2，说明感染类型为Ramnit.A
//返回3，该文件没有被感染
int Ramnit::JudgeRamnitType(char fileName[MAX_PATH])
{
	this->RamnitType = 3;
	this->fileType = JudgeFileType(fileName);	//判断文件类型
	if (this->fileType == 0)					//当文件为PE文件
	{
		if (!MapFile(fileName))
		{
			this->RamnitType = 3;
			return 0;		//返回0，打开文件失败
		}							
		else
		{
			if (JudgeSection())
			{
				this->RamnitType = 1;
				return 1;						//返回1，说明感染类型为Ramnit.x或Ramnit.AS
			}
			else
			{
				CloseAllHandle();
				if (JudgeCharacteristic(fileName,0))
				{
					this->RamnitType = 2;
					return 2;					//返回2，说明感染类型为Ramnit.A
				}
				else
				{
					this->RamnitType = 3;
					return 3;					//返回3，该文件没有被感染
				}
			}
		}
		CloseAllHandle();
	}
	else if (this->fileType == 1)				//当文件为html文件
	{
		if (JudgeCharacteristic(fileName,3))
		{
			this->RamnitType = 2;
			return 2;							//返回2，说明感染类型为Ramnit.A
		}
		else
		{
			char Buffer[20];
			HANDLE hfile;
			DWORD NumberOfBytesRead;
			SetFileAttributesA(fileName, FILE_ATTRIBUTE_NORMAL);
			hfile = CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hfile != INVALID_HANDLE_VALUE)
			{
				DWORD filesize = GetFileSize(hfile, 0);
				if (filesize != -1)
				{
					SetFilePointer(hfile, -14, 0, FILE_END);
					ReadFile(hfile, Buffer, 14, &NumberOfBytesRead, 0);
					if (strcmp(Buffer, "//--></SCRIPT>") == 0)
					{
						this->RamnitType = 1;
						return 1;				//返回1，说明感染类型为Ramnit.x或Ramnit.AS
					}
					else
					{
						this->RamnitType = 3;
						return 3;				//返回3，该文件没有被感染
					}
					CloseHandle(hfile);
				}
			}
			else
				CloseHandle(hfile);					
		}
	}
	else
	{
		this->RamnitType = 3;
		return 3;								//文件没有被感染
	}
}

/*/需要写
void FixRemovAble(char *str_disk)
{
/*/

//遍历当前磁盘全部文件
void Ramnit::TraverseAllFile(char* str_disk)
{
	char path[MAX_PATH] = { 0 };
	WIN32_FIND_DATAA FindFileData;
	HANDLE hFindFile;
	lstrcpyA(path, str_disk);
	lstrcatA(path, "*.*");
	hFindFile = FindFirstFileA(path, &FindFileData);//开始遍历当前磁盘文件
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (!ExcludeFile(FindFileData.cFileName))
			{
				lstrcpyA(path, str_disk);
				lstrcatA(path, FindFileData.cFileName);	//拼接文件绝对路径
				if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					int lenthofpath = lstrlenA(path);
					if (lenthofpath)
					{
						if (path[lenthofpath - 1] != '\\')
							path[lenthofpath] = '\\';	//添加反斜杠	
						path[lenthofpath + 1] = 0;
						lenthofpath = 0;
					}
					if (!JudgeFilePath(path))			//判断是否是system和windows目录
						TraverseAllFile(path);			//递归遍历
				}
				else
				{
					int filetype = JudgeFileType(path);
					if (filetype == 0 || filetype == 1)
					{
						JudgeRamnitType(path);				//判断感染类型，以及感染文件类型
						if (this->RamnitType == 1)			//当感染类型为 1
							repair1(path);					//修复1
						else if (this->RamnitType == 2)		//当感染类型为 2
							repair2(path);					//修复2
					}
				}
			}
		} while (FindNextFileA(hFindFile, &FindFileData));
	}
}

//修复Ramnit.x或Ramnit.AS
void Ramnit::repair1(char filename[MAX_PATH])			
{
	if(this->fileType==0)							//修复PE文件
	{
		if (!MapFile(filename))						//映射文件到内存中
		{
			return;
		}
		printf("----------------------------------------------------------------------------------------\n");
		printf("|%s文件\n", filename);
		printf("|开始修复文件！\n");

		DWORD RAW = sectionHeader[numOfSection - 1].PointerToRawData;
		DWORD median = *(PDWORD)((PBYTE)dosHeader + RAW + 0x328);
		OEP = optionalHeader->AddressOfEntryPoint - median;
		printf("|成功获取到原始OEP：%x\n", OEP);									//获取正确的OEP
		optionalHeader->AddressOfEntryPoint = OEP;	//修正OEP
		FixSection();								//删除多余节表
		DWORD Distance = (sectionHeader[numOfSection - 2].SizeOfRawData + sectionHeader[numOfSection - 2].PointerToRawData);
		CloseAllHandle();							//关闭句柄
		//修正文件大小
		HANDLE hFile1 = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		SetFilePointer(hFile1, Distance, 0, FILE_BEGIN);
		SetEndOfFile(hFile1);
		printf("|修复完成!\n");
		printf("-----------------------------------------------------------------------------------------\n");
		printf("\n");
		CloseHandle(hFile1);
	}
	else					//修复html
	{
		repairHtml1(filename);
	}
}

//修复Ramnit.A
void Ramnit::repair2(char filename[MAX_PATH])
{
	if (this->fileType == 0)					//修复PE文件
	{
		if (!MapFile(filename))						//映射文件到内存中
		{
			return;
		}
		printf("----------------------------------------------------------------------------------------\n");
		printf("|%s文件\n", filename);
		printf("|开始修复文件！\n");

		DWORD RAW = sectionHeader[numOfSection - 1].PointerToRawData;
		DWORD median = *(PDWORD)((PBYTE)dosHeader + RAW + 0x771);
		OEP = optionalHeader->AddressOfEntryPoint - median;
		printf("|成功获取到原始OEP：%x\n", OEP);									//获取正确的OEP
		optionalHeader->AddressOfEntryPoint = OEP;	//修正OEP
		FixSection();								//删除多余节表
		DWORD Distance = (sectionHeader[numOfSection - 2].SizeOfRawData + sectionHeader[numOfSection - 2].PointerToRawData);
		CloseAllHandle();							//关闭句柄
		//修正文件大小
		HANDLE hFile1 = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		SetFilePointer(hFile1, Distance, 0, FILE_BEGIN);
		SetEndOfFile(hFile1);
		printf("|修复完成!\n");
		printf("-----------------------------------------------------------------------------------------\n");
		printf("\n");
		CloseHandle(hFile1);
	}
	else					//修复html
	{
		repairHtml2(filename);	
	}
}
