#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/stat.h> 
#include <fcntl.h>

// unique id used to validate identity when connecting
const int u_id = 5512;

// error handler
// takes msg to print and boolean for whether to use perror 
// or normal error output. (perror used when errno is set)
void error(const char *msg, int perrorOutput) 
{ 
	if(perrorOutput)
	{
		perror(msg);
		exit(1); 
	}
	else
	{
		fprintf(stderr,"%s\n",msg);
		exit(1); 
	}
} 

// forward declarations
int performHandshake(int *server);
int checkText(FILE* checkMe);
void packageData(char** package, FILE* src);
void sendPackage(int *server, char* toSend);
void receiveCipher(char** cipher, int *socketFD);

// main
int main(int argc, char *argv[])
{

	// socket descriptor and portNumber
    int socketFD, portNumber;
	// below structs used to build and connect to server
    struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;

	// confirm correct number of arguments was received. If not, print out usage.   
    if (argc < 4) { fprintf(stderr,"USAGE: %s textfilename keyfilename port\n", argv[0]); exit(0); } // Check usage & args

    /*open text file and check it*/
	//hold path for file, and set to empty
    char textPath[64];
	memset(textPath, '\0', sizeof(char));

	// add leading ./ to look in current dir
    strcat(textPath,"./");

	//add file name to path
    strcat(textPath, argv[1]);

	// open the file
    FILE* textFP = fopen(textPath,"r");

	if(textFP == NULL) // error opening
		error("Error opening text file.",1);

	/*open key file and check it*/
	// hold path and set to empty
	char keyPath[64];
    memset(keyPath, '\0', sizeof(char));
	// build up path/file name
    strcat(keyPath,"./");
	strcat(keyPath, argv[2]);
   
	// open the key file
    FILE* keyFP = fopen(keyPath,"r");
	if(keyFP == NULL) // error opening
		error("Error opening key file.",1);

	// stores the length of the two files if they are properly validated
	// if an invalid character is found, it is set to -3 
    int lengthPlaintext = checkText(textFP);
    int lengthKey = checkText(keyFP);
	
	// use lengthPlaintext to allocate room for the ciphertext we will receive back
	char* cipherText = calloc(sizeof(char) * lengthPlaintext,sizeof(char));

	// pointers to hold the 'packaged' contents of the key and text files
	char *textPackage = NULL;
	char *keyPackage = NULL;

	// check if either file has invalid character (set to -3 in checkText)
	if (lengthPlaintext == -3)
		error("Invalid character detected in text message.", 0);
	else if (lengthKey == -3)
		error("Invalid character detected in key.", 0);
	else if (lengthPlaintext > lengthKey) // check if the key is at least as long as text file
    {
		error("Key length is too short.",0);
    }
	else // files passed validation
	{
		// after this call, textPackage will contain the entire text and key file will contain the entire key
		// packages are terminated by a '?'
		packageData(&textPackage, textFP);
		packageData(&keyPackage, keyFP);

		// done with files, closing
		fclose(keyFP);
		fclose(textFP);
    }
   
	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("eos-class.engr.oregonstate.edu"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket\n", 1);
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting",1);

	// perform handshake (confirm program is able to connect to the indicated server)
	int connectionAccepted = performHandshake(&socketFD);

	// if connection accepted is true (connected to otp_enc_d)
	if(connectionAccepted)
	{
		// send the text package
		sendPackage(&socketFD, textPackage);	
		// free the textPackage memory
		free(textPackage);
		
		// send the key package
		sendPackage(&socketFD, keyPackage);	
		// free key package memory
		free(keyPackage);
	}
	else // server returned a false for handshake, meaning it will not accept connections from otp_enc
	{
		error("Error. otp_dec_d will not accept connections from otp_enc.",0);
	}

	// Get ciphertext from server and print it out
	receiveCipher(&cipherText,&socketFD);	
	
	printf("%s\n",cipherText);

	
	//close socket
	close(socketFD); // Close the socket
	return 0;
}

// Prepares for and receives the encoded text from otp_enc_d
// Accepts: char** for where to store the cipher and a int* for the socket to receive on
void receiveCipher(char** cipher, int *socketFD)
{
	// check read amount
	int charsRead = 1;

	//boolean for checking if terminating character is reached
	int terminatorFound = 0;

	//iterate through cipher to place at right point
	int cipherIter = 0;

	// hold read infor before stuffing into cipher
	char* tmpBuffer = calloc(sizeof(char)*70000,sizeof(char));

	//clear strings
	memset(tmpBuffer, '\0', sizeof(tmpBuffer));
	memset(*cipher, '\0', sizeof(*cipher)); // Clear out the buffer again for reuse
	
	// while we are still receiving data and the terminator has not been reached
	while(charsRead > 0 && !terminatorFound)
	{
		// receive up to 70000 characters worth of data
		charsRead = recv(*socketFD, tmpBuffer, sizeof(tmpBuffer), 0); // Read data from the socket, leaving \0 at end
		
		// copy character by character into cipher from tmpBuffer
		int i;
		for(i = 0; i < strlen(tmpBuffer); i++)
		{
			// check if terminator is found
			if(tmpBuffer[i] == '?')
			{
				// flip flag and break out
				terminatorFound = 1;
				break;
			}
			// otherwise insert character into cipher and increment the iterator
			(*cipher)[cipherIter] = tmpBuffer[i];
			cipherIter++;
		}

		//reset to empty
		memset(tmpBuffer, '\0', sizeof(tmpBuffer));
	}
}	


// Checks to ensure text in passed in file is valid and counts the length of the text
// Accepts a FILE* to the file we are checking
// return value is either the length of the text, or -3 if an invalid character was found
int checkText(FILE* checkMe)
{
	// hold the last character read
	char tmp;
	int charsRead = 0;
	
	// read a single character
	tmp = fgetc(checkMe);

	//increment count
	charsRead++;

	// while newline and EOF are not reached
	while(tmp != '\n' && tmp != EOF)
	{
		
		// if character's ascii value is less than 65 (A) or greater than 90 (Z)
		if(tmp < 65 || tmp > 90)
		{
			// if out of the range, check if it is 32 (space)
			if(tmp != 32)
			{
				//if it is not a space, return -3 to indicate an invalid
				//character has been found
				return -3;
			}
		}
		// good character found, so read next character and increment
		tmp = fgetc(checkMe);
		charsRead++;
	}

	// return count of characters
	return charsRead;
}

// Reads text from a file into a character string (package)
// Accepts char** package to store text in, FILE* src for source file
void packageData(char** package, FILE* src)
{
	// rewind file to start
	rewind(src);
	// hold character read
	char* temp;

	// get length of each file to properly allocate memory
	// go to end of text file
	if(fseek(src,0, SEEK_END) == 0)
	{
		long Bufsize = ftell(src); //get size of text file
		if(Bufsize == -1)
			error("Error occurred in finding file length.",1);

		// allocate package to the size of the file
		*package = calloc((sizeof(char) * Bufsize) + 1 ,sizeof(char));// '+1' is to accomodate the ? character used to terminate the msg

		//rewind file to beginning
		rewind(src);
		size_t readSize = fread(*package,sizeof(char),(Bufsize - 1),src); // read text into package first
		strcat(*package,"?");// '?' is used to identify the end of the text and start of the key
	}
}

// Performs handshake with server to confirm it is connecting with otp_enc_d
// Accepts int* for the server we are connecting to
// Returns 1 or 0 indicating if connection is accepted or refused
// Accepted: connecting to otp_enc_d. Refused: connecting to otp_dec_d.
int performHandshake(int *server)
{
	// hold unique id string
	char temp[4];
	
	// holds value for return
	int responseCode = 0;

	// copy u_id into temp string
	sprintf(temp,"%d",u_id);
	// send string to server
	int dataSent = send(*server,temp,strlen(temp),0);
	if(dataSent < 0)
		error("Error sending handshake.",1);
	if(dataSent < strlen(temp))
		error("Not all data was written",0);

	// to receive response
	char handshakeResponse[2];
	memset(handshakeResponse,'\0',5);

	// read response
	int read = recv(*server,handshakeResponse,sizeof(handshakeResponse)-1,0);

	if(read != 1)
		error("Error reading from server.",1);

	// convert string response into integer and return value
	responseCode = atoi(handshakeResponse);
	return(responseCode);		
}	


// Sends the provided text package to the indicated server
// Accepts int* server for where to send file and char* toSend, the package to be sent
void sendPackage(int *server, char* toSend)
{
	// store the number of bytes to send
	long int bytesToSend = strlen(toSend);
	
	// set to zero to ensure accurate counts
	long int bytesSent = 0;
	long int totalSent = 0;
	
	// loop to send until all data sent
	while(totalSent < bytesToSend)
	{
		// send data and store in bytesSent
		bytesSent = send(*server, toSend + totalSent, 1024,0);
		
		// add to totalSent
		totalSent += bytesSent;
	}

}	

