#pragma once
#include <windows.h>
class Ramnit
{
private:
	int RamnitType;
	int fileType;
public:
	Ramnit();
	void Traverserepair();
	int JudgeRamnitType(char fileName[MAX_PATH]);
	void repair1(char filePath[MAX_PATH]);
	void repair2(char filePath[MAX_PATH]);
	void TraverseAllFile(char* str_disk);
};



