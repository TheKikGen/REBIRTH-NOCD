/* Win32 Process Launch Patcher
   By 360trev - Adapted by The KikGen
   
   Simple tool to runtime patch memory of a newly create PE Process
   (executable). It using a CSV config file to define the patch bytes to change.

   This is great for debugging/patching binaries, e.g. to test ALL possible routes
   through you code without actually changing the source-code or re-compiling.
   Just identifying the bytes (see my disassembler project) and then patch them
   in runtime with the config file!

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
   AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
   OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <processenv.h>
#include <tchar.h>
#include <string.h>



#define MAXFLDS		   1024  /* maximum possible number of fields		 */
#define MAXFLDSIZE     32  /* longest possible field + 1 = 31 byte field  */

/* don't forget to add the correct PE section offset to your byte offset in your
 * CSV patchfile, that's the segment offset + file byte offset.
 *
 * - see tutorial for more information.
 * e.g. code segment is usually 0x400000 in PE files. See a PE viewer for more info
 */


static char arr[MAXFLDS][MAXFLDSIZE];

void parse_csv(char* record, char* delim, char arr[][MAXFLDSIZE], int* fldcnt)
{
	char* p = strtok(record, delim);
	int fld = 0;

	while (p) {
		strcpy(arr[fld], p);

		if (*(arr[fld]) == '\n') {}
		else {
			fld++;
		}
		p = strtok((char *)'\0', delim);
	}
	*fldcnt = fld;
}

int main(int argc, char* argv[])
{
	char tmp[1024] = { 0x0 };
	int fldcnt = 0, field = 0;
	int recordcnt = 0;
	long value;
	FILE* in;
	STARTUPINFO          si;
	PROCESS_INFORMATION  pi;
	wchar_t targetProcessName[1024] = { 0 };

	unsigned long NumBytesWrote = 0;
	unsigned long NumBytesRead = 0;
	void* cur_offset = 0;
	unsigned char cur_old = 0;
	unsigned char cur_new = 0;
	unsigned char cur_mem = 0;


	printf("PELaunch 1.2 [ In Memory PE Launcher & Patcher ]\n");
	printf("(c) The KikGen Labs.  Original credit to 360trev.\n");
	printf("-------------------------------------------------\n\n");

	if (argc < 3) { printf("Usage: %s <exe to launch> <patch csvfile>\n", argv[0]); return 0; }

	printf("> Opening CSV patch file '%s'...", argv[2]);
	// open file
	if ((in = fopen(argv[2], "r")) == NULL) {
		printf("*** Fatal error : file not found.\n\n");
		return -1;
	}

	printf("OK.\n");

	SetCurrentDirectoryA(0);	// set current dir...

	// Start the process

	printf("> Launching process '%s'...", argv[1]);
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	
	MultiByteToWideChar(0, 0, argv[1], strlen(argv[1]), targetProcessName, strlen(argv[1]));

	// CreateProcess() requires LPCWSTR (or wchar_t*, respectively)
	if (CreateProcess(0, targetProcessName, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi))

	{
		printf("OK.\n");

		printf("> Patching memory...\n");

		while (fgets(tmp, sizeof(tmp), in) != 0) {
			
			// Check any comment # line at the first position
			if (*tmp == '#') continue;

			field = 0;
			parse_csv(tmp, (char *) ",", arr, &fldcnt);
			recordcnt++;
			for (field = 0;field < fldcnt;field++)
			{
				sscanf(arr[field], "%lx", &value);
				switch (field)
				{
				case 0: { cur_offset = (void*)value;        break;  }		// csv field 1
				case 1: { cur_old    = (unsigned char)value; break; }	    // csv field 2
				case 2: { cur_new    = (unsigned char)value; break; }		// csv field 3
				default: break;
				}
			}

			ReadProcessMemory((HANDLE)pi.hProcess, (LPVOID)cur_offset, &cur_mem, 1, (SIZE_T*)&NumBytesRead);
			printf("     @%p  :  Memory = %2.2x  Old byte = %2.2x  Patched byte = %2.2x -> ", cur_offset,cur_mem, cur_old, cur_new);

			// Verify old byte vs memory before patching
			if (cur_mem == cur_old) {
				WriteProcessMemory((HANDLE)pi.hProcess, (LPVOID)cur_offset, &cur_new, 1, (SIZE_T*)&NumBytesWrote);
				printf("OK. %ld bytes written.\n", NumBytesWrote);
			}
			else {
				printf("*** Fatal error : memory and old bytes not matching.\n");
				break;
			}
		}
		printf("\n> Done..resume process.\n");
		ResumeThread(pi.hThread);
		// close
		if (in != 0) { fclose(in); }
	}
	else
	{
		printf("*** Fatal error : process failed to open.\n\n");
		return 1;
	}
	return 0;
}
