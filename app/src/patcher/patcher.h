#pragma once
#include <iostream>
#include <fstream>
#include <vector>

namespace patcher 
{
	bool patch_pe(const std::string& filename);
}
