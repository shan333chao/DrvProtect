#include "../Memmory/MiMemory.h"

namespace patternSearch {

	inline BOOL  bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	inline DWORD FindSectionOffset(QWORD dwAddress, QWORD dwLen, BYTE* bMask, char* szMask);
	inline QWORD FindPatternEx(QWORD dwAddress, QWORD dwLen, BYTE* bMask, char* szMask);

}