#pragma once
#include <chrono>
#include <ctime>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <vector>
#include <winternl.h>
#include <cstdint>
#include <DbgHelp.h>
#include <thread>
#include <functional>
#include <map>
#include <algorithm>
#include <numbers>
#include <type_traits>
#include <dwmapi.h>
#include <unordered_set>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

#include <dependencies/oxorany/include.h>
#include <dependencies/hexrays/hexrays.h>
#include <workspace/utilities/logger.hxx>

#include <workspace/driver/ia32.h>
#include <workspace/driver/control.h>
#include <workspace/driver/driver.hxx>
auto g_driver = std::make_shared<driver::c_driver>( );

#include <workspace/utilities/crash.hxx>
#include <workspace/utilities/utility.hxx>

#include<workspace/utilities/imports/apiset.hxx>
auto g_apiset = std::make_shared<apiset::c_apiset>( );

#include<workspace/utilities/imports/imports.hxx>
#include<workspace/dependency/dependency.hxx>