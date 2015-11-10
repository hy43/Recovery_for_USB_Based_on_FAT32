 
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

#define U8     unsigned char
#define S8     char
#define U16   unsigned short
#define U32   unsigned int
#define U64   unsigned __int64
#define PARTITION_TBL_POS	0x1BE
// MBR 영역에서 0~446 Byte 이후에 실제 Partition Table이 등장하므로 따로 기록
/*
* ------------- 구조체설명 -----------------
* PARTITION : partition 의 정보를 담기위한 구조체
* FAT32_BPB : BPB 의정보를담기위한구조체
* VolStruct : FAT32_BPB 에서 필요한 정보를 추출하기위한 구조체
* DitEntry : Directory Entry 의 정보를 저장하기 위한 구조체
* LongDirEntry : LFN의 Directory Entry를 저장하기 위한 구조체
*/

#pragma pack(1)
// 컴파일러의구조체패딩을막기위한선언
typedef struct _PARTITION{
	/*
	* --------- 구조체변수설명 ------------
	* BootFlag : 파티션의 부팅 가능 여부 확인 0x80 부팅 가능, 0x00 부팅 불가능
	* CHS_Start : CHS 방식의 파티션 시작 섹터
	* Type : 파티션 종류
	* CHS_End : CHS 방식의 파티션 종료 섹터
	* LBA_Start : LBA 방식의 파티션 시작 섹터
	* length : 볼륨내 총 섹터 수
	* ---------------------------------------
	*/
	U8 BootFlag;
	U8 CHS_Start[3];
	U8 type;
	U8 CHS_End[3];
	U32 LBA_Start;
	U32 length;
}PARTITION, *PPARTITION;
#pragma pack()

#pragma pack(1)
typedef struct _FAT32_BPB_struct{
	/*
	* --------- 구조체변수설명 ------------
	* 1. BPB 공통영역(1)
	* JmpBoot[3] : 부트코드로점프하기위한주소
	* OEMName[8] : OEM 회사이름
	* BytesPerSec : 섹터당바이트수
	* SecPerClus : 클러스터당섹터수
	* RsvdSecCnt : 예약된영역의섹터수
	* NumFATs : 볼륨내의FAT 영역의갯수로일반적으로 2개
	* RootEntCnt : FAT32 에서는'0'
	* TotSec16 : FAT32 에서는'0'
	* Media : 0xF8
	* FATs16 : FAT32 에서는'0'
	* SecPerTrk : '0' 더이상참조하지않는다
	* NumHeads : '0' 더이상참조하지않는다
	* HiddSec : '0' 더이상참조하지않는다
	* TotSec32 : 볼륨상에존재하는총섹터수
	* 2. BPB FAT32 영역
	* FATs32 : FAT 영역의섹터수
	* ExtFlags : FAT Table 에대한설정값 , 일반적으로0x00
	* FileSysVer : FAT32 의버전정보 , 0x00
	* RootDirClus : 루트디렉토리클러스터의위치
	* FileSysInfo : FSInfo 구조체의위치로일반적으로볼륨의 1번섹터에위치
	* BootBakSec : BR 의백업클러스터위치
	* Reserved[12] : 예약된영역으로 0으로채워진다
	* DirNum : 참조하지않는다
	* Reserv1 : 0 으로채워진다
	* BootSign : 0x29 로고정
	* VolID : 볼륨의시리얼번호
	* volLabel[11] : 해당파티션의볼륨레이블
	* FileSysType[8] : FAT32 라는문자열이들어간다
	* 3. BPB 공통영역(2)
	* BootCodeArea : BootCode 들어있다.
	* Signature : BR 의손상여부확인을위해 0xAA55 로고정
	* ---------------------------------------
	*/
	U8 JmpBoot[3];
	U8 OEMName[8];
	U16 BytesPerSec;
	U8 SecPerClus;
	U16 RsvdSecCnt;
	U8 NumFATs;
	U16 RootEntCnt;
	U16 TotSec16;
	U8 Media;
	U16 FATs16;
	U16 SecPerTrk;
	U16 NumHeads;
	U32 HiddSec;
	U32 TotSec32;
	// BPB 공통영역
	U32 FATs32;
	U16 ExtFlags;
	U16 FileSysVer;
	U32 RootDirClus;
	U16 FileSysInfo;
	U16 BootBakSec;
	U8 Reserved[12];
	U8 DirNum;
	U8 Reserv1;
	U8 BootSign;
	U32 VolID;
	U8 volLabel[11];
	U8 FileSysType[8];
	// BPB FAT32 영역
	U8 BootCodeArea[420];
	U16 Signature;
}FAT32_BPB;
#pragma pack()

#pragma pack(1)
typedef struct _VOL_struct{
	/*
	* --------- 구조체변수설명 ------------
	* Drive
	* VolBeginSec
	* FirstDataSec : 첫번째 데이터 섹터
	* RootDirSec : Root Directory의 시작 섹터
	* RootDirSecCnt : Root Directory의 총 섹터 수
	* RootEntCnt : Root Directory의 Directory Entry 개수
	* FATSize : FAT 영역의 섹터 수
	* FATStartSec : FAT 영역 시작점
	* TotalClusCnt : 볼륨의 총 클러스터 수
	* TotalSec : 볼륨의 총 섹터
	* DataSecSize : 데이터 영역의 섹터수
	* ClusterSize : 클러스터 크기
	* SecPerClus : 한개 클러스터의 섹터 수
	* ---------------------------------------
	*/
	U32 Drive;
	U32 VolBeginSec;
	U32 FirstDataSec;
	U32 RootDirSec;
	U32 RootEntCnt;
	U32 RootDirSecCnt;
	U32 FATSize;
	U32 FATStartSec;
	U32 TotalClusCnt;
	U32 TotalSec;
	U32 DataSecSize;
	U32 ClusterSize;
	U32 SecPerClus;
}VolStruct;
#pragma pack()

#pragma pack(1)
typedef struct _DIR_struct{
	/*
	* --------- 구조체변수설명 ------------
	* Name[11] : 파일/디렉토리 명 + 확장자
	* Attr : 파일 종류 ex) 0x04 시스템, 0x10 Directory 0x20 Archive File 0xF0 LFNs
	* NTRes : 0 고정
	* CrtTimeTenth : 생성 시간
	* CrtTime : 생성 시간
	* CrtDate : 생성 일자
	* LstAccDate : 접근 날짜
	* FstClusHi : 파일/디렉토리의 첫 번째 클러스터의 상위 2Byte
	* WriteTime : 수정 시간
	* WriteDate : 수정 일자
	* FstClustLow : 파일/디렉토리의 첫 번째 클러스터의 하위 2Byte
	* FileSize : 파일 크기
	* ---------------------------------------
	*/
	U8 Name[11];
	U8 Attr;
	U8 NTRes;
	U8 CrtTimeTenth;
	U16 CrtTime;
	U16 CrtDate;
	U16 LstAccDate;
	U16 FstClusHi;
	U16 WriteTime;
	U16 WriteDate;
	U16 FstClustLow;
	U32 FileSize;
}DirEntry;
#pragma pack()

#pragma pack(1)
typedef struct _LONG_DIR_struct{
	/*
	* --------- 구조체변수설명 ------------
	* Order : LFN 순번 저장 
	* Name1+Name2+Name3 : 파일 명 
	* Attr : 0x0F 고정
	* Type : 예약으로 0 rhwjd
	* chksum : Short Directory Entry 의 Checksum 저장
	& FstClusLo : 0 고정
	* ---------------------------------------
	*/
	U8 Order;
	U8 Name1[10];
	U8 Attr;
	U8 Type;
	U8 chksum;
	U8 Name2[12];
	U16 FstClusLo;
	U8 Name3[4];
}LongDirEntry;
#pragma pack()

/*
* ------------- 함수설명-----------------
* HDD_read : 저장장치로부터섹터를읽어와메모리에담기위한함수
* HDD_write : 저장장치의섹터에데이터를쓰기위한함수
* HexDump : Dump된 Memory를 Hex로 보여주기 위한 함수(점검용)
* get_partition : 파티션 정보 및 BPB 시작주소의 획득을 위한 함수
* get_BPB_info : BPB 의정보를구조체에저장하기위한함수
* print_longName : LFNs를 출력하기 위한 함수
* show_dir : Root Directory Entry를 출력하기 위한 함수(점검용)
* show_del_dir : 삭제된 Directory Entry를 출력하기 위한 함수
* rec_file : 파일 복구를 위한 함수
* rec_dir : 디렉토리 복구를 위한 함수
* -----------------------------------------
*/

U32 HDD_read(U8 drv, U32 SecAddr, U32 blocks, U8* buf);
U32 HDD_write(U8 drv, U32 SecAddr, U32 blocks, U8* buf);
void HexDump  (U8 *addr, U32 len);
void get_partition(PPARTITION pPartition, U8 pSecBuf[512]);
U32 get_BPB_info(FAT32_BPB* BPB, VolStruct* pVol);
void print_longName(LongDirEntry* pLongDir, U32 EntryNum);
U32 show_dir(DirEntry* pDir);
U32 show_del_dir(DirEntry* pDir);
U32 rec_file(DirEntry* pDir,U32 rec_entry, U32* fat_entry, U32 Flag, U32 upClus);
U32 rec_dir(DirEntry* pDir, U32 useClus);

VolStruct gVol;

int main()
{
	/*
	* ------------- 변수설명-----------------
	* mbr_buf : mbr 영역의 덤프를 위한 버퍼
	* bpb_buf : bpb 영역의 덤프를 위한 버퍼
	* fat_buf : fat 영역의 덤프를 위한 버퍼
	* pPartition_arr : 파티션 정보 저장을 위한 구조체 변수
	* root_buf : Root Directory Entry 영역의 덤프를 위한 버퍼
	* sel_m_menu : 메인 메뉴에서의 선택을 위한 변수
	* sel_rec_entry : 복구하고자 하는 디렉토리 엔트리 입력 변수
	* -----------------------------------------
	*/

	U32 sel_m_menu;
	U32 sel_rec_entry;

	U8 mbr_buf[512];
	U8 bpb_buf[512];
	U32 fat_buf[128];
	U8* root_buf;
	PARTITION pPartition_arr[50];

	gVol.Drive = 0x2;
	gVol.VolBeginSec = 0x0;
	// 초기 HDD 덤프를 위한 장치번호와 시작 섹터 초기화

 	if(HDD_read(gVol.Drive, gVol.VolBeginSec, 1, mbr_buf)== 0)
	{
		printf( "Boot Sector Read Failed \n" );
		return 1;
	}
	// mbr 영역의 덤프를 위한 HDD_read 함수 호출
	
	get_partition(pPartition_arr, mbr_buf);
	// mbr 덤프를 이용한 파티션 정보 습득을 위한 get_partition 함수 호출
	
	gVol.VolBeginSec = pPartition_arr->LBA_Start;
	// 시작 위치를 Partition의 시작 섹터로 변경
	if(HDD_read(gVol.Drive, gVol.VolBeginSec, 1, bpb_buf)==0)
	{
		printf( "BPB Sector Read Failed \n");
		return 1;
	}
	// BPB 영역의 덤프를 위한 HDD_read 함수 호출

	if(get_BPB_info((FAT32_BPB *)bpb_buf, &gVol) == 0)
	{
		printf( "It is not FAT32 File System \n" );
		return 1;
	}
	// BPB 영역의 정보를 구조체에 저장하기 위한 get_BPB_info 함수 호출

	gVol.RootDirSecCnt = 10;
	gVol.RootEntCnt = 100;
	// Root Directory Entry 내 섹터를 읽어오기 위한 변수 설정
	/*
	* ---------------- 개선해야할 사항 ---------------- 
	* 단 고정된 값이 아니라 가변적인 값으로 처리할 방법을 구상해야함
    * ------------------------------------------------- 
	*/

	root_buf = (U8*)malloc(gVol.RootDirSecCnt*512);
	// Root Directory Entry 공간만큼의 동적할당

	if(HDD_read(gVol.Drive, gVol.RootDirSec, gVol.RootDirSecCnt, root_buf)==0)
	{
		printf("Root Directory Read Failed \n");
		return 1;
	}

	printf("============= USB Recovery Tool Ver.FAT32 =============\n");
	printf("1. Analyze USB \n");
	printf("2. Exit \n");
	printf("select 1 or 2 : ");
	scanf("%d", &sel_m_menu);
	// 메인 메뉴 출력 및 변수 입력

	switch(sel_m_menu)
	{
	case 1:
		show_del_dir((DirEntry*)root_buf);
		break;
	case 2:
		exit(1);
	}
	// 메인 메뉴 입력 변수에 따른 분기를 위한 switch 문
	// 1 : 지워진 파일/디렉토리 출력
	// 2 : 프로그램 종료

	printf("\n\n============= Recovery Mode =============\n");
	printf("복구하고자 하는 파일의 Entry Number를 입력하세요 : ");
	scanf("%d", &sel_rec_entry);
	// 복구 모드 출력 및 복구할 Directory Entry 선택

	if(HDD_read(gVol.Drive,gVol.FATStartSec, 1, fat_buf)==0)
	{
		printf( "FAT Sector Read Failed \n");
		return 1;
	}
	// FAT 영역의 덤프를 위한 HDD_read 함수 호출

	rec_file((DirEntry*)root_buf,sel_rec_entry,fat_buf, 0, 0);
	// 데이터의 복구를 위한 rec_file 함수 호출
	
	return 0;
}

U32 HDD_read(U8 drv, U32 SecAddr, U32 blocks, U8* buf)
{
	/*
	* ------------- 변수설명-----------------
	* drv : 접근하고자하는물리장치
	* SecAddr : 시작섹터설정을위한변수
	* blocks : 읽어올섹터수
	* buf : 해당섹터에대한 dumpdata
	* ret : 해당장치의존재유무반환용변수
	* ldistanceLow : 하위23bit 저장
	* ldistanceHigh : 상위9bit 저장
	* dwpointer : 시작섹터
	* bytestoread : 파일을읽을단위설정
	* numread : 읽은바이트수
	* cur_drv : 접근하고자하는드라이브명 ex) \\.\PhysicalDrive0
	* g_hDevice : 파일핸들
	* -----------------------------------------
	*/

	U32 ret;
	U32 ldistanceLow, ldistanceHigh, dwpointer, bytestoread, numread;
	char cur_drv[100];
	HANDLE g_hDevice;

	sprintf(cur_drv, "\\\\.\\PhysicalDrive%d" ,(U32)drv);
	// CreateFIle을통한PhysicalDrive로의접근을위한문자열생성

	g_hDevice = CreateFile(cur_drv, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	// CreateFile을활용한PhysicalDrive 접근용파일핸들생성

	if(g_hDevice==INVALID_HANDLE_VALUE)      return 0;
	// 해당디바이스존재여부에따른분기

	ldistanceLow = SecAddr << 9;
	ldistanceHigh = SecAddr >> (32-9);
	// ldistanceLow 하위 9 bit, ldistanceHigh 상위 23 bit 저장

	dwpointer = SetFilePointer(g_hDevice, ldistanceLow, ( long *)&ldistanceHigh, FILE_BEGIN);
	// 시작섹터설정

	if(dwpointer != 0xFFFFFFFF)
	{
		bytestoread = blocks * 512; // 읽어올데이터길이
		ret = ReadFile(g_hDevice, buf, bytestoread, ( unsigned long*)&numread, NULL);
		if(ret)       ret = 1;
		else ret = 0;
	}

	CloseHandle(g_hDevice);
	// 핸들종료
	return ret;
}

U32 HDD_write(U8 drv, U32 SecAddr, U32 blocks, U8* buf)
{
	/*
	* ------------- 변수설명-----------------
	* drv : 접근하고자하는물리장치
	* SecAddr : 시작섹터설정을위한변수
	* blocks : 읽어올섹터수
	* buf : 해당섹터에대한 dumpdata
	* ret : 해당장치의존재유무반환용변수
	* ldistanceLow : 하위23bit 저장
	* ldistanceHigh : 상위9bit 저장
	* dwpointer : 시작섹터
	* bytestoread : 파일을읽을단위설정
	* numread : 읽은바이트수
	* cur_drv : 접근하고자하는드라이브명 ex) \\.\PhysicalDrive0
	* g_hDevice : 파일핸들
	* -----------------------------------------
	*/

	U32 ret = 0;
	U32 ldistanceLow, ldistanceHigh, dwpointer, bytestoread, numread;
	char cur_drv[100];
	HANDLE g_hDevice;

	sprintf(cur_drv, "\\\\.\\PhysicalDrive%d" ,(U32)drv);
	// CreateFIle을통한PhysicalDrive로의접근을위한문자열생성

	g_hDevice = CreateFile(cur_drv, GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	// CreateFile을활용한PhysicalDrive 접근용파일핸들생성

	if(g_hDevice==INVALID_HANDLE_VALUE)      return 0;
	// 해당디바이스존재여부에따른분기

	ldistanceLow = SecAddr << 9;
	ldistanceHigh = SecAddr >> (32-9);

	dwpointer = SetFilePointer(g_hDevice, ldistanceLow, ( long *)&ldistanceHigh, FILE_BEGIN);
	// 시작섹터설정

	if(dwpointer != 0xFFFFFFFF)
	{
		bytestoread = blocks * 512; // 읽어올데이터길이
		ret = WriteFile(g_hDevice, buf, bytestoread, ( unsigned long*)&numread, NULL);
		if(ret)       ret = 1;
		else ret = 0;
	}

	CloseHandle(g_hDevice);
	// 핸들종료
	return ret;
}

void HexDump  (U8 *addr, U32 len){

	U8            *s=addr, *endPtr=(U8*)((U32)addr+len);
	U32           i, remainder=len%16;

	printf( "\n Offset        Hex Value         Ascii value\n" );

	// print out 16 byte blocks.
	while (s+16<=endPtr){

		// offset 출력
		printf( "0x%08lx  " , (long)(s-addr));

		// 16 bytes 단위로내용출력
		for (i=0; i<16; i++){
			printf( "%02x ", s[i]);
		}
		printf( " ");

		for (i=0; i<16; i++){
			if (s[i]>=32 && s[i]<=125)printf("%c", s[i]);
			else printf("." );
		}
		s += 16;
		printf( "\n");
	}

	// Print out remainder.
	if (remainder){

		// offset 출력
		printf( "0x%08lx  " , (long)(s-addr));

		// 16 bytes 단위로출력하고남은것출력
		for (i=0; i<remainder; i++){
			printf( "%02x ", s[i]);
		}
		for (i=0; i<(16-remainder); i++){
			printf( "   " );
		}

		printf( " ");
		for (i=0; i<remainder; i++){
			if (s[i]>=32 && s[i]<=125) printf("%c", s[i]);
			else   printf(".");
		}
		for (i=0; i<(16-remainder); i++){
			printf( " ");
		}
		printf( "\n");
	}
	return;
}      // HexDump.

void get_partition(PPARTITION pPartition, U8 pSecBuf[512])
{
	memcpy(pPartition, (pSecBuf + PARTITION_TBL_POS), sizeof(PARTITION));
	// Partition 추출
}

U32 get_BPB_info(FAT32_BPB* BPB, VolStruct* pVol)
{
	if(BPB->RootEntCnt != 0 || BPB->Signature != 0xAA55)   return 0;
	// Root Directory & Signature 의이상유무를판단하여분기

	pVol->TotalSec = BPB->TotSec32;
	// Get Total Sector
	pVol->FATSize = BPB->FATs32;
	// Get FAT Size
	pVol->FATStartSec = pVol->VolBeginSec + BPB->RsvdSecCnt;
	// Get FAT Start Sector
	pVol->RootEntCnt = BPB->RootEntCnt;
	//Get Root Directory Entry Count
	pVol->RootDirSec = pVol->VolBeginSec + BPB->RsvdSecCnt + (BPB->NumFATs * BPB->FATs32);
	//Get Root Directory Sector
	pVol->FirstDataSec = pVol->VolBeginSec + BPB->RsvdSecCnt + (BPB->NumFATs * pVol->FATSize) + pVol->RootDirSecCnt;
	// Get FAT Start Sector
	pVol->DataSecSize = pVol->TotalSec - (BPB->RsvdSecCnt + (BPB->NumFATs * pVol->FATSize) + pVol->RootDirSecCnt);
	// Get Size Of Data Area
	pVol->TotalClusCnt = pVol->DataSecSize / BPB->SecPerClus;
	//Get Total Cluster Count
	pVol->ClusterSize = BPB->SecPerClus * BPB->BytesPerSec;
	//Get Size Of Cluster
	pVol->SecPerClus = BPB->SecPerClus;
	// Get Sector Per Cluster
	return 1;
}

U32 show_dir(DirEntry* pDir)
{
	/*
	 * ------------- 변수설명-----------------
	 * i,j : 반복 변수
	 * LongEntryEn : LFNs 검출용 변수
	 * -----------------------------------------
	 */

	U32 i, j, LongEntryEn=0;

	for(i=0;i<=gVol.RootEntCnt;i++)
	{
		switch((U8) pDir[i].Name[0])
		{
		case 0x00:
			// End Of Entry
			return 1; 
		case 0xE5 :
			// delete of Entry
			continue;
		}
		// Directory Entry 의 상태 확인
		
		if(pDir[i].Attr == 0x0F)
		{
			LongEntryEn = 1;
			// Long File Name Entry
			continue;
		}
		// LFNs Directory Entry 구분

		printf("------------------------- Entry Number %d -------------------------\n",i);

		if(pDir[i].Attr == 0x10)
			printf("Directory Name : ");
		else
			printf("File Name : ");
		// Directory or File Name is

		if(LongEntryEn == 1)
		{
			print_longName((LongDirEntry*)pDir, i-1);
			LongEntryEn = 0;
		} // LFNs 인 경우의 파일/디렉토리 이름 출력
		else
		{
			for(j=0;j<11;j++)
				printf("%c",pDir[i].Name[j]);
		} // Short Name 출력
		printf("\n");

		printf("File Size : %d\n",pDir[i].FileSize);
		printf("Start Cluster : %d\n",(pDir[i].FstClustLow | pDir[i].FstClusHi << 16));
		// First Cluster Low/High 를 전체 출력
	}
	return 1;
}

void print_longName(LongDirEntry* pLongDir, U32 EntryNum)
{
	/*
	 * ------------- 변수설명-----------------
	 * filename : LFNs 파일 명으로 합치기 위한 배열(Name1 + Name2 + Name3)
	 * final : filename을 유니코드 방식으로 변경한 최종 파일 명
	 * nameOffset : LFNs Entry 에서의 Name%d 이동을 위한 변수
	 * -----------------------------------------
	 */
	wchar_t filename[512];
	char final[512];
	U32 nameOffset = 0;

	do{
		memcpy(&filename[nameOffset],pLongDir[EntryNum].Name1, 10);
		// Name1에 저장된 이름 문자열 복사
		nameOffset += 5; 
		// Name1 속성에서 Name2 속성으로 이동
		memcpy(&filename[nameOffset],pLongDir[EntryNum].Name2, 12);
		// Name2에 저장된 이름 문자열 복사
		nameOffset += 6;
		// Name2 속성에서 Name3 속성으로 이동
		memcpy(&filename[nameOffset],pLongDir[EntryNum].Name3, 4);
		// Name3에 저장된 이름 문자열 복사
		nameOffset += 2;

	}while((pLongDir[EntryNum--].Order & 0x40)==0);
	// 0x40과 or 연산한 것이 가장 마지막 LFNs

	filename[nameOffset] = 0x0000;
	// 문자열의 끝을 알리는 0x0000 저장

	wcstombs(final,filename, 512);
	// 유니코드->아스키코드로 변환
	printf("%s",final);
}

U32 show_del_dir(DirEntry* pDir)
{
	/*
	 * ------------- 변수설명-----------------
	 * i,j : 반복 변수
	 * LongEntryEn : LFNs 검출용 변수
	 * -----------------------------------------
	 */

	U32 i, j, LongEntryEn=0;

	for(i=0;i<=gVol.RootEntCnt;i++)
	{
		if((U8) pDir[i].Name[0] == 0x00)
			return 1;
		else if((U8) pDir[i].Name[0] != 0xE5)
			continue;
		// Directory Entry 의 상태 확인
		
		if(pDir[i].Attr == 0x0F)
		{
			LongEntryEn = 1;
			// Long File Name Entry
			continue;
		}
		// LFNs Directory Entry 구분

		printf("------------------------- Entry Number %d -------------------------\n",i);

		//if(pDir[i].Attr != 0x04
		if(pDir[i].Attr == 0x10)
			printf("Directory Name : ");
		else
			printf("File Name : ");
		// Directory or File Name is

		if(LongEntryEn == 1)
		{
			print_longName((LongDirEntry*)pDir, i-1);
			LongEntryEn = 0;
		} // LFNs 인 경우의 파일/디렉토리 이름 출력
		else
		{
			for(j=0;j<11;j++)
				printf("%c",pDir[i].Name[j]);
		} // Short Name 출력
		printf("\n");

		printf("File Size : %d\n",pDir[i].FileSize);
		printf("Start Cluster : %d\n",(pDir[i].FstClustLow | pDir[i].FstClusHi << 16));
		// First Cluster Low/High 를 전체 출력
	}
	return 1;
}

U32 rec_file(DirEntry* rData, U32 rec_entry, U32* fat_entry, U32 Flag, U32 upClus)
{
	/*
	 * ------------- 변수설명-----------------
	 * i : 반복 변수
	 * useClus : 빈 클러스터
	 * reset_buf : 빈 클러스터 초기화용 버퍼
	 * rec_buf : 파일 내용 백업용 버퍼
	 * dir_buf : 디렉토리를 복구할 경우의 서브 디렉토리의 Directory Entry 덤프를 위한 버퍼
	 * FstClustNum : 첫 번째 클러스터를 저장하기 위한 변수
	 * StartSec : 복구 시작 섹터 저장을 위한 변수 -> 최초에는 Root Directory Sector에서 복구가 진행되지만
	 *            그 이후 부터는 Sub Directory에서 진행되기 때문에 고정값 X
	 * Flag : 0 -> Root Directory, 1 -> Sub Directory
	 * upClus : 상위 디렉토리의 클러스터 번호
	 * -----------------------------------------
	 */

	U32 i, useClus;
	U8 reset_buf[4096];
	U8 rec_buf[4096];
	U8 dir_buf[4096];
	U32 FstClustNum;
	U32 StartSec;


	memset(reset_buf, 0x00, sizeof(reset_buf)); // 초기화용 메모리 제작(0x00 으로 전체 초기화 시킴)
	memset(rec_buf, 0x00, sizeof(rec_buf)); // 복제 메모리 초기화
	
	FstClustNum = rData[rec_entry].FstClustLow | rData[rec_entry].FstClusHi << 16;
	// First Cluster Total 저장 
	
	HDD_read(gVol.Drive, gVol.RootDirSec + (FstClustNum - 2)*gVol.SecPerClus, 8, rec_buf);
	// 파일 내용 복사
	
	for(i=0;;i++)
	{
		if(fat_entry[i] == 0x00000000)
		{
			useClus = i;
			// 빈 클러스터 발견 시 해당 클러스터 번호 useClus에 저장
			break;
		}	
	}
	// for(;;)
	// FAT 영역에서의 빈 클러스터 검색
	// -------------------------------------------------------------------------------------- 삭제 파일 복구(적용 X)
	fat_entry[useClus] = 0x0FFFFFFF;
	// 빈 클러스터를 사용 클러스터로 변경
	rData[rec_entry].Name[0] = 'R';
	// 삭제 시그니쳐 0xE5 -> R 문자열로 변경
	// -------------------------------------------------------------------------------------- 삭제 파일 복구(적용 X)
	
	// -------------------------------------------------------------------------------------- 복구 내용 적용 구간
	HDD_write(gVol.Drive, gVol.RootDirSec + (useClus-2)*gVol.SecPerClus, 8, reset_buf);
	// 사용할 클러스터 초기화
	if(Flag == 0) 
	{	
		StartSec = gVol.RootDirSec;
		Flag = 1;
	}
	else
	{
		StartSec = gVol.RootDirSec + (upClus - 2 ) * gVol.SecPerClus;
	} // Root Directory와 Sub Directory 에 따른 Directory Entry 의 시작 주소 변경을 위한 분기

	rData[rec_entry].FstClustLow = useClus;
	// 삭제 이전 클러스터 -> 사용할 클러스터 
	HDD_write(gVol.Drive, gVol.RootDirSec + (useClus-2)*gVol.SecPerClus, 8, rec_buf);
	// 백업해둔 파일 내용 새로운 클러스터에 복사
	HDD_write(gVol.Drive, StartSec, 8, rData);
	// 삭제 시그니쳐 -> R 시그니처 적용
	HDD_write(gVol.Drive, gVol.FATStartSec, 8, fat_entry);
	// 빈 클러스터 ->  사용 클러스터 변경 내용 적용
	// -------------------------------------------------------------------------------------- 복구 내용 적용 구간
	
	/*
	* ---------------- 개선해야할 사항 ---------------- 
	* 해당 파일의 크기가 1 Cluster 를 넘어갈 때의 복구
	* ------------------------------------------------- 
	*/
	if(rData[rec_entry].Attr == 0x10)
	{		
		StartSec = gVol.RootDirSec + (FstClustNum - 2 ) * gVol.SecPerClus;
		// Sub Directory Entry 의 시작 위치
		HDD_read(gVol.Drive, StartSec, 8, dir_buf);
		// Sub Directory Entry Dump
		rec_dir(dir_buf, Flag, useClus);
		// Directory 에 대한 복구를 위한 rec_dir 함수 호출
	}// 해당 Directory Entry가 Directory 일 경우의 복구
	
	printf("%s 이/가 복구 완료 되었습니다. \n", rData[rec_entry].Name);
	// 복구된 파일/디렉토리 명과 완료 메세지 출력

	return 0;
}

U32 rec_dir(DirEntry* pDir, U32 Flag, U32 useClus)
{
	/*
	 * ------------- 변수설명-----------------
	 * i : 반복 변수
	 * pDir : Sub Directory 의 Dump 를 담는 버퍼
	 * U32 Flag : 0 -> Root Directory, 1 -> Sub Directory
	 * useClus : 현재 디렉토리의 클러스터 번호
	 * FstClustNum : 해당 Directory Entry 가 사용하는 클러스터 번호( != useClus)
	 * fat_buf : fat Table Entry를 담기위한 버퍼
	 * -----------------------------------------
	 */

	U32 i;
	U32 FstClustNum;
	U32 fat_buf[128];

	for(i=0;pDir[i].Name[0]!=0x00;i++)
	{
		FstClustNum = pDir[i].FstClustLow | pDir[i].FstClusHi << 16;
		if(FstClustNum == 0x00000000 || pDir[i].Name[0] != 0xE5)
		{
			continue;
		}// 클러스터 할당 여부 확인
		else
		{
			if(HDD_read(gVol.Drive,gVol.FATStartSec, 1, fat_buf)==0)
			{
				printf( "FAT Sector Read Failed \n");
				return 1;
			}
			// FAT 영역의 덤프를 위한 HDD_read 함수 호출
			rec_file(pDir, i, fat_buf, Flag, useClus);
		}
	}
	return 0;
}	 
