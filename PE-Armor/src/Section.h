/*******************************************************
/*《加密与解密》第三版配套实例
/*第16章 外壳编写基础
/*
/*Code by Hying 2001.1
/*Modified by kanxue  2005.3
/*Thanks ljtt
/*Hying原来的外壳主程序是asm，kanxue用VC改写，改写过程，参考了ljtt的外壳源码
/*(c)  看雪软件安全网站 www.pediy.com 2000-2008
********************************************************/

#ifndef _SECTION_H_
#define _SECTION_H_

/*-------------------------------------------------------------*/
/*  CalcMinSizeOfData                                   －     */
/* 搜索并去掉尾部无用的零字节，重新计算区块的大小             */
/*-------------------------------------------------------------*/

UINT CalcMinSizeOfData(PCHAR pSectionData, UINT nSectionSize)
{

	if (IsBadReadPtr(pSectionData, nSectionSize))
	{
		return nSectionSize;
	}

	PCHAR	pData = &pSectionData[nSectionSize - 1];
	UINT	nSize = nSectionSize;

	while (nSize > 0 && *pData == 0)
	{
		pData --;
		nSize --;
	}

	return nSize;
}

/*-------------------------------------------------------------*/
/*  IsSectionCanPacked                                         */
/* 判断当前区块数据能否被压缩                                  */
/*-------------------------------------------------------------*/

BOOL IsSectionCanPacked(PIMAGE_SECTION_HEADER psecHeader)
{
//	ASSERT(psecHeader != NULL);

	UINT  nExportAddress=0;
	const UINT	nListNum = 6;
	LPCTSTR		lpszSecNameList[nListNum] =
	{
		".text",
		".data",
		".rdata",
		"CODE",
		"DATA",
		".reloc",
	};

	nExportAddress = m_pntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;


	// 如果发现匹配的区块名称，则表示此区块可以压缩
	for (UINT nIndex = 0; nIndex < nListNum; nIndex ++)
	{

		//有些输出表可能会在.rdata等区块，如果区块合并了就不能这样判断了
		if(!IsMergeSection)
		{
			if((nExportAddress >= psecHeader->VirtualAddress) && ( nExportAddress < (psecHeader->VirtualAddress+psecHeader->Misc.VirtualSize) ) )
			return FALSE;
		}

		if (strncmp((char *)psecHeader->Name, lpszSecNameList[nIndex], strlen(lpszSecNameList[nIndex])) == 0)
		{
			return TRUE;
		}
	}


	// 否则其他区块都不能压缩
	return FALSE;
}

/*-------------------------------------------------------------*/
/*  MergeSection －合并区段
将开始的一些可以压缩的区段合并,可以缩小一些压缩后文件的大小
经过此函数后融合生成的区段只有映象大小和映象偏移有用,文件大
小和文件偏移在压缩回写时修正.
/*-------------------------------------------------------------*/
BOOL MergeSection()
{
	UINT					nSectionNum = 0;
	PIMAGE_SECTION_HEADER	psecHeader = m_psecHeader;
	UINT					nspareSize=NULL;
	UINT					nMergeVirtualSize =0;

	try
	{
		nSectionNum   = m_pntHeaders->FileHeader.NumberOfSections;
		
		for (UINT nIndex = 0; nIndex < nSectionNum; nIndex ++, psecHeader ++)
		{
			if ((m_psecHeader->Characteristics & IMAGE_SCN_MEM_SHARED) != 0)//共享区块不融合
				break;		

			if ((strcmp((char *)psecHeader->Name, ".edata") == 0))
				break;

			if ((strcmp((char *)psecHeader->Name, ".rsrc") == 0))
				break;			

			nMergeVirtualSize += psecHeader->Misc.VirtualSize;
		}
		m_psecHeader->Misc.VirtualSize = nMergeVirtualSize;
		m_pntHeaders->FileHeader.NumberOfSections = nSectionNum - nIndex+1;// 现在的区块数
		//(nIndex+1)*sizeof(IMAGE_SECTION_HEADER)//;剩余区块表的长度
		memcpy(m_psecHeader+1,psecHeader,(nSectionNum - nIndex)*sizeof(IMAGE_SECTION_HEADER));//将剩余的区块移前
		nspareSize=(nSectionNum - m_pntHeaders->FileHeader.NumberOfSections)*sizeof(IMAGE_SECTION_HEADER);//多余区块长度
		memset(m_psecHeader+nSectionNum - nIndex+1,0,nspareSize);		


	}
	catch (...)
	{
		return FALSE;
	}
	return TRUE;

}
/*-------------------------------------------------------------*/
/*  ClsSectionName－ 清空区块名								   */
/*-------------------------------------------------------------*/
void ClsSectionName()
{
	UINT					nSectionNum = 0;
	PIMAGE_SECTION_HEADER	psecHeader = m_psecHeader;
	
	nSectionNum   = m_pntHeaders->FileHeader.NumberOfSections;		
	for (UINT nIndex = 0; nIndex < nSectionNum; nIndex ++, psecHeader ++)
	{
		memset(psecHeader->Name, 0, 8);
	}
}

#endif