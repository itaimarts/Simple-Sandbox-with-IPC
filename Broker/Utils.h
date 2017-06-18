#pragma once

#include "stdafx.h"

void convertcharArrToPWSTR(char * src, PWSTR * tar);
void ErrorExit(LPTSTR lpszFunction);
char * GetWindowObjectName(HANDLE handle);
