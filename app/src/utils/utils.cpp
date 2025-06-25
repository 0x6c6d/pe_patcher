#include "utils.h"

DWORD utils::AlignUp(DWORD val, DWORD align)
{
	return (val + align - 1) & ~(align - 1);
}