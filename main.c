#include <Windows.h>
#include <stdint.h>

uint64_t probeaddr;

int handler(PEXCEPTION_POINTERS ctx)
{
	if (ctx->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		if (ctx->ContextRecord->Rdi % 8)
		{
			return EXCEPTION_EXECUTE_HANDLER;
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

// assumes the page you want to monitor has 1 valid & present page preceeding it
// as a supplemental buffer to ensure ermsb reaches its fast path
int probe_page(uint64_t page)
{
	int detecc = 0;
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	ctx.Dr0 = page + 8;
	ctx.Dr7 = 0x30001;
	
	SetThreadContext(GetCurrentThread(), &ctx);

	void* destination = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);

	memset(destination, 0, 0x2000);

	__try
	{
		__movsb((PBYTE)destination, (PBYTE)(page - 0x1000), 0x2000);
	}
	__except (handler(GetExceptionInformation()))
	{
		detecc = 1;
	}

	VirtualFree(destination, 0, MEM_RELEASE);

	return detecc;
}

typedef void(__fastcall* func)();

int main()
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

	void* codepages = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//page it all in
	memset(codepages, 0, 0x2000);

	//setup our function
	*((uint8_t*)codepages + 0x1000) = 0xc3;

	printf("\nMonitoring function address: 0x%016llX\n", ((uint64_t)codepages + 0x1000));

	while (1)
	{
		if (probe_page((uint64_t)codepages + 0x1000))
		{	
			printf("\rEPT hook status: \033[33mDETECTED\033[0m");
		}
		else
		{
			printf("\rEPT hook status: \033[32mPASS\033[0m    ");                 
		}

		Sleep(500);
	}

	return 0;
}