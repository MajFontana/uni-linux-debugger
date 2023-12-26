#include <stdio.h>



int counter = 0;



void add(int x)
{
    counter += x;
}


int main()
{
    while (counter < 16)
    {
        printf("counter = %d\n", counter);
        
        add(2);
        add(-1);
    }

    return 0;
}