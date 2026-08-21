// autosar_misra_violation_test.cpp

#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <locale.h>

using namespace std;          // AUTOSAR M7-3-4

register int GlobalCounter;   // AUTOSAR A7-1-4

#define const                 // MISRA 20.4

long double PiValue = 3.14L;  // AUTOSAR A0-4-2

wchar_t TextValue;            // AUTOSAR A2-14-3

int DataArray[10];            // AUTOSAR A18-1-1

std::vector<bool> Flags;      // AUTOSAR A18-1-2

void BadFunction()
{
    printf("Violation\n");    // MISRA 21.6

    void* Buffer = malloc(100);   // MISRA D4.12 / 21.3

    if (Buffer)
    {
        free(Buffer);             // MISRA D4.12 / 21.3
    }

    int ErrorCode = 5;

    if (ErrorCode)                // MISRA 14.4
    {
        printf("Error\n");
    }

    int ShiftResult = 1 << 32;    // MISRA 12.2

    int* Ptr = DataArray;

    Ptr += 1;                     // AUTOSAR M5-0-15

    int Result = (ErrorCode > 0) ? 100 : 200;

    int FinalValue = Result + ((ErrorCode > 2) ? 10 : 20);
                                  // AUTOSAR A5-16-1

    do                            // AUTOSAR A6-5-3
    {
        ErrorCode--;
    }
    while (ErrorCode > 0);

    std::abort();                 // AUTOSAR A15-5-2
}

int main()
{
    BadFunction();
    return 0;
}