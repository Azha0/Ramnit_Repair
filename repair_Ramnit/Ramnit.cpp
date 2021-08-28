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

//ӳ��Ŀ���ļ�
DWORD MapFile(char filename[MAX_PATH])
{
	//ӳ���ļ����ڴ���
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
//�ų�. ..��RMNetwork
int ExcludeFile(char* string)
{
	return !lstrcmpA(string, ".") || !lstrcmpA(string, "..") || !lstrcmpA(string, "RMNetwork");
}

//�ж��Ƿ���system��windowsĿ¼
int JudgeFilePath(char* string)
{
	if (!lstrcmpA(string, "C:\\Windows\\") || !lstrcmpA(string, "C:\\Windows\System32\\"))
		return 1;
	return 0;
}

//�ж��ļ�����
int JudgeFileType(char path[MAX_PATH])
{
	LPCSTR suffix = PathFindExtensionA(path);
	if (!lstrcmpA(suffix, ".exe") || !lstrcmpA(suffix, ".dll"))
	{
		return 0;			//����0����ʾ��ǰ�ļ�Ϊexe�ļ�����dll�ļ�
	}
	else if (!lstrcmpA(suffix, ".htm") || !lstrcmpA(suffix, ".html"))
	{
		return 1;			//����1�����ʾ��ǰ�ļ�Ϊhtm��html
	}
	else
		return 2;
}

//�޸�html1
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
			printf("|%s�ļ�\n", filepath);
			printf("|��ʼ�޸��ļ���\n");
			SetFilePointer(hfile, filesize - 280034, 0, FILE_BEGIN);				
			SetEndOfFile(hfile);
			CloseHandle(hfile);
			printf("|�޸����!\n");
			printf("-----------------------------------------------------------------------------------------\n");
			printf("\n");
		}
	}
	else
		CloseHandle(hfile);
}

//�޸�html2
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
			printf("|%s�ļ�\n", filepath);
			printf("|��ʼ�޸��ļ���\n");
			SetFilePointer(hfile, filesize - 539, 0, 0);				//539Ϊ����������ݵ���󳤶�
			ReadFile(hfile, Buffer, 539, &NumberOfBytesRead, 0);	//��ȡ�ļ�ĩβ539�ֽڵ����ݵ�buffer��
			const char strcharacteristic[20] = "</SCRIPT><!--";
			char* ret = strstr(Buffer, strcharacteristic);
			DWORD Distance = filesize - (262630 + (539 - (ret - Buffer) - 13));
			printf("|ԭʼ�ļ���СΪ��%d\n",Distance);
			SetFilePointer(hfile, Distance, 0, FILE_BEGIN);
			SetEndOfFile(hfile);
			CloseHandle(hfile);
			printf("|�޸����!\n");
			printf("-----------------------------------------------------------------------------------------\n");
			printf("\n");

		}
	}
	else
		CloseHandle(hfile);
}

//�رվ��
void CloseAllHandle()
{
	UnmapViewOfFile(hFileMapAddr);
	CloseHandle(hMap);
	CloseHandle(hFile);
}

//�ж�.rmnet�ڱ��Ƿ���� 
//����1��˵��rmnet�ڴ���
//����0��˵��rmnet�ڲ�����
BOOL JudgeSection()
{
	char* sectionName = (char*)sectionHeader[numOfSection - 1].Name;
	if (strcmp(sectionName, ".rmnet") == 0)
	{
		return 1;//����1��˵��rmnet�ڱ����
	}
	return 0;//����0��˵���ڱ�����
}

//�ж��ļ�ĩβ�ĸ�Ⱦ����  ����true��˵�����ļ�����Ⱦ
//flag = 0 ΪPE�ж�
//flag = 3 Ϊ��ҳ�ж�
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
				return true;	//����true��˵�����ļ�����Ⱦ
			else
				return false;	//����false��˵�����ļ�û�б���Ⱦ�����ǲ����ڸ��ļ�����
		}
		else
		{
			printf("���ļ�ʧ�ܣ�");
			CloseHandle(hfile);
			return false;		//�ļ���С������������û�б���Ⱦ
		}

	}
	else
		return false;		//�ļ���ʧ��
}

//ɾ������ڱ�
void FixSection()
{
	//ɾ������ڱ�����
	optionalHeader->SizeOfImage -= sectionHeader[numOfSection - 1].Misc.VirtualSize;  //����sizeofimage  
	memset(sectionHeader[numOfSection - 1].PointerToRawData + (PBYTE)dosHeader, 0, sectionHeader[numOfSection - 1].SizeOfRawData);

	//����DOSͷ								
	fileHeader->NumberOfSections--;	//�ڱ����-1
	memset(&sectionHeader[numOfSection - 1], 0, 0x28);	//�����һ���ڵ�����ȫ��0
	printf("|�ɹ��޸�����ڱ�\n");
}


Ramnit::Ramnit()
{
	this->fileType = 2 ;		//���Ǹ�Ⱦ�ļ�
	this->RamnitType = 3;		//�ļ�û�б���Ⱦ
}

//����
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
			printf("	��ʼ�޸����̣�%s\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
			TraverseAllFile(i);
			printf("*************************************\n");
			printf("*************************************\n");
			printf("	����%s���޸����\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
		}
		else if ( type == DRIVE_REMOVABLE )
		{
			printf("*************************************\n");
			printf("*************************************\n");
			printf("	��ʼ�޸����ƶ����� ��%s\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
			//FixRemovAble(i);
			printf("*************************************\n");
			printf("*************************************\n");
			printf("	����%s���޸����\n", i);
			printf("*************************************\n");
			printf("*************************************\n");
		}
	}
}

//�жϸ�Ⱦ���ͣ�����1��˵����Ⱦ����ΪRamnit.x��Ramnit.AS
//����0�����ļ�ʧ��
//����1��˵����Ⱦ����ΪRamnit.x��Ramnit.AS
//����2��˵����Ⱦ����ΪRamnit.A
//����3�����ļ�û�б���Ⱦ
int Ramnit::JudgeRamnitType(char fileName[MAX_PATH])
{
	this->RamnitType = 3;
	this->fileType = JudgeFileType(fileName);	//�ж��ļ�����
	if (this->fileType == 0)					//���ļ�ΪPE�ļ�
	{
		if (!MapFile(fileName))
		{
			this->RamnitType = 3;
			return 0;		//����0�����ļ�ʧ��
		}							
		else
		{
			if (JudgeSection())
			{
				this->RamnitType = 1;
				return 1;						//����1��˵����Ⱦ����ΪRamnit.x��Ramnit.AS
			}
			else
			{
				CloseAllHandle();
				if (JudgeCharacteristic(fileName,0))
				{
					this->RamnitType = 2;
					return 2;					//����2��˵����Ⱦ����ΪRamnit.A
				}
				else
				{
					this->RamnitType = 3;
					return 3;					//����3�����ļ�û�б���Ⱦ
				}
			}
		}
		CloseAllHandle();
	}
	else if (this->fileType == 1)				//���ļ�Ϊhtml�ļ�
	{
		if (JudgeCharacteristic(fileName,3))
		{
			this->RamnitType = 2;
			return 2;							//����2��˵����Ⱦ����ΪRamnit.A
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
						return 1;				//����1��˵����Ⱦ����ΪRamnit.x��Ramnit.AS
					}
					else
					{
						this->RamnitType = 3;
						return 3;				//����3�����ļ�û�б���Ⱦ
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
		return 3;								//�ļ�û�б���Ⱦ
	}
}

/*/��Ҫд
void FixRemovAble(char *str_disk)
{
/*/

//������ǰ����ȫ���ļ�
void Ramnit::TraverseAllFile(char* str_disk)
{
	char path[MAX_PATH] = { 0 };
	WIN32_FIND_DATAA FindFileData;
	HANDLE hFindFile;
	lstrcpyA(path, str_disk);
	lstrcatA(path, "*.*");
	hFindFile = FindFirstFileA(path, &FindFileData);//��ʼ������ǰ�����ļ�
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (!ExcludeFile(FindFileData.cFileName))
			{
				lstrcpyA(path, str_disk);
				lstrcatA(path, FindFileData.cFileName);	//ƴ���ļ�����·��
				if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					int lenthofpath = lstrlenA(path);
					if (lenthofpath)
					{
						if (path[lenthofpath - 1] != '\\')
							path[lenthofpath] = '\\';	//��ӷ�б��	
						path[lenthofpath + 1] = 0;
						lenthofpath = 0;
					}
					if (!JudgeFilePath(path))			//�ж��Ƿ���system��windowsĿ¼
						TraverseAllFile(path);			//�ݹ����
				}
				else
				{
					int filetype = JudgeFileType(path);
					if (filetype == 0 || filetype == 1)
					{
						JudgeRamnitType(path);				//�жϸ�Ⱦ���ͣ��Լ���Ⱦ�ļ�����
						if (this->RamnitType == 1)			//����Ⱦ����Ϊ 1
							repair1(path);					//�޸�1
						else if (this->RamnitType == 2)		//����Ⱦ����Ϊ 2
							repair2(path);					//�޸�2
					}
				}
			}
		} while (FindNextFileA(hFindFile, &FindFileData));
	}
}

//�޸�Ramnit.x��Ramnit.AS
void Ramnit::repair1(char filename[MAX_PATH])			
{
	if(this->fileType==0)							//�޸�PE�ļ�
	{
		if (!MapFile(filename))						//ӳ���ļ����ڴ���
		{
			return;
		}
		printf("----------------------------------------------------------------------------------------\n");
		printf("|%s�ļ�\n", filename);
		printf("|��ʼ�޸��ļ���\n");

		DWORD RAW = sectionHeader[numOfSection - 1].PointerToRawData;
		DWORD median = *(PDWORD)((PBYTE)dosHeader + RAW + 0x328);
		OEP = optionalHeader->AddressOfEntryPoint - median;
		printf("|�ɹ���ȡ��ԭʼOEP��%x\n", OEP);									//��ȡ��ȷ��OEP
		optionalHeader->AddressOfEntryPoint = OEP;	//����OEP
		FixSection();								//ɾ������ڱ�
		DWORD Distance = (sectionHeader[numOfSection - 2].SizeOfRawData + sectionHeader[numOfSection - 2].PointerToRawData);
		CloseAllHandle();							//�رվ��
		//�����ļ���С
		HANDLE hFile1 = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		SetFilePointer(hFile1, Distance, 0, FILE_BEGIN);
		SetEndOfFile(hFile1);
		printf("|�޸����!\n");
		printf("-----------------------------------------------------------------------------------------\n");
		printf("\n");
		CloseHandle(hFile1);
	}
	else					//�޸�html
	{
		repairHtml1(filename);
	}
}

//�޸�Ramnit.A
void Ramnit::repair2(char filename[MAX_PATH])
{
	if (this->fileType == 0)					//�޸�PE�ļ�
	{
		if (!MapFile(filename))						//ӳ���ļ����ڴ���
		{
			return;
		}
		printf("----------------------------------------------------------------------------------------\n");
		printf("|%s�ļ�\n", filename);
		printf("|��ʼ�޸��ļ���\n");

		DWORD RAW = sectionHeader[numOfSection - 1].PointerToRawData;
		DWORD median = *(PDWORD)((PBYTE)dosHeader + RAW + 0x771);
		OEP = optionalHeader->AddressOfEntryPoint - median;
		printf("|�ɹ���ȡ��ԭʼOEP��%x\n", OEP);									//��ȡ��ȷ��OEP
		optionalHeader->AddressOfEntryPoint = OEP;	//����OEP
		FixSection();								//ɾ������ڱ�
		DWORD Distance = (sectionHeader[numOfSection - 2].SizeOfRawData + sectionHeader[numOfSection - 2].PointerToRawData);
		CloseAllHandle();							//�رվ��
		//�����ļ���С
		HANDLE hFile1 = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		SetFilePointer(hFile1, Distance, 0, FILE_BEGIN);
		SetEndOfFile(hFile1);
		printf("|�޸����!\n");
		printf("-----------------------------------------------------------------------------------------\n");
		printf("\n");
		CloseHandle(hFile1);
	}
	else					//�޸�html
	{
		repairHtml2(filename);	
	}
}
