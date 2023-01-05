#include "features.h"

int main()
{
   if (!file.Start("C:\\Users\\User\\source\\repos\\mapper_for_csgo\\TestDll.dll"))
        printf("failed open module\n");

    printf("waiting process...\n");
    while (game::process_id == 0)
    {
        game::attach("csgo.exe");
        Sleep(100);
    }
    printf("attached to process!\n");

    mapper::process_mapping();
    mapper::call_entry();
}

