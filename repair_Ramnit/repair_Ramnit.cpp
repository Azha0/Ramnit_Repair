#include <iostream>
#include <windows.h>
#include <shlwapi.h>
#include "Ramnit.h"
#pragma comment(lib,"shlwapi.lib")
using namespace std;

int main()
{
	FILE* stream1;
	int option;
	Ramnit BOX;
	int type;
	printf("***Ramnit专杀工具***\n");
	printf("====================\n");
	printf("|选项0 全盘查杀修复|\n|选项1 指定文件修复|\n");
	printf("====================\n");
	printf("请输入修复选项：");
	scanf_s("%d",&option);
	getchar();									//接收回车
	char filename[MAX_PATH] = { 0 };
	switch (option)
	{
	case 0:
		printf("修复完成程序自动退出，修复日志在当前目录下！\n");
		freopen_s(&stream1, "FixResult.txt", "w", stdout);
		BOX.Traverserepair();						//遍历修复可执行文件
		fclose(stdout);
		break;
	case 1:
		printf("请输入要恢复的文件路径:");
		gets_s(filename, MAX_PATH);
		switch (BOX.JudgeRamnitType(filename))	//根据文件路径，判断被感染类型
		{
		case 0:
			printf("文件映射失败\n");
			break;
		case 1:
			printf("该文件的感染类型为:Ramnit.x或Ramnit.AS\n"); 
			BOX.repair1(filename);					//修复变种Ramnit.x或Ramnit.AS
			system("pause");
			break;
		case 2:
			printf("该文件的感染类型为:Ramnit.A\n");
			BOX.repair2(filename);					//修复变种Ramnit.A
			system("pause");
			break;
		case 3:
			printf("该文件没有被感染！\n");
			break;
		}
		break;
	default:
		printf("输入有误，默认全盘修复！");
		printf("修复完成程序自动退出，修复日志在当前目录下！\n");
		freopen_s(&stream1, "FixResult.txt", "w", stdout);
		//BOX.Traverserepair();						//遍历修复可执行文件
		fclose(stdout);
		break;
	}
	return 0;
}


