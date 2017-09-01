#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> 

int main(int argc, char *argv[])
{
	// ensure valid args are provided
	if(argc != 2)
	{
		fprintf(stderr,"USAGE: %s length\n", argv[0]); 
		exit(1);
	}
		
	// convert to int
	int keylength = atoi(argv[1]);
	
	//seed random generator
	srand(time(NULL));
	
	// loop to generate 'keylength' random characters
	int i;
	for(i = 0; i < keylength; i++)
	{
		char tmpChar;
		
		// get int from 0-26
		int tmpInt = rand() % 27;
		
		// if 0, set to space (ascii 32)
		if(tmpInt == 0)
			tmpChar =(char)  32;
		else
		{
			// conver value to capital letter ASCII by adding 64
			tmpChar = (char) tmpInt + 64;
		}
		//write out
		write(STDOUT_FILENO, &tmpChar, 1);
	}
	// add newline
	char newline = '\n';
	write(STDOUT_FILENO, &newline, 1);
	
	return 0;
}
