#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>


// store string values for accept and deny responses to the handshake
const char handshakeAccept = '1';
const char handshakeDeny = '0';

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
int handshakeVerify(int *identifyMe);
void retrievePackage(int *estCon, char** receivedFile);
void encodeText(char** cipher, char* plain, char* key);
void sendCiphertext(char* cipher, int *estCon);
void catchSIGINT();
void checkOnTheKids();

// global flag to tell server to keep listening
// set to 0 via SIGINT. Ensures that socket is closed.
int keepListening = 1;

// for catching SIGINT
struct sigaction SIGINT_action = {0};

int main(int argc, char *argv[])
{

	// Create and initialize handler for SIGINT
	SIGINT_action.sa_handler = catchSIGINT;
	sigfillset(&SIGINT_action.sa_mask);
	SIGINT_action.sa_flags = 0;
	SIGINT_action.sa_flags = SA_RESTART; // any read,write,open in progress when signal is received will be restarted
	sigaction(SIGINT, &SIGINT_action, NULL); // catch and redirect to function

	// listen and connected socket descriptors and portNumber
	int listenSocketFD, establishedConnectionFD, portNumber;

	// used to connect
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress;

	// verify correct number of args provided and print usage if not
	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	
	// set to non blocking
	fcntl(listenSocketFD,F_SETFL, O_NONBLOCK);

	if (listenSocketFD < 0) 
		error("ERROR opening socket",1);
		
	// hold client address
	struct sockaddr_in clientAddress;
		
	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("ERROR on binding",1);
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	// while sigint is not received
	while(keepListening)
	{
		// check for terminated / exited child processes
		checkOnTheKids();

		// Accept a connection, blocking if one is not available until one connects and then fork connected socket off into child process
		pid_t spawn;
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		
		// if no connection, check if EAGAIN or EWOULDBLOCK is received indicating no attempts
		if (establishedConnectionFD < 0)
		{
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			else //error accepting = bad
				error("Error on accept.",0);
		}
		else // valid connection accepted
		{
			spawn = fork(); // fork off onto child process 
			if(spawn < 0)
				error("ERROR spawning child process",0);
		}

		if(spawn == 0) // 0 is child process, if not child, restarts at top of loop to keep listening
		{
			// handshake to verify otp_enc is connecting
			int clientApproved = handshakeVerify(&establishedConnectionFD);

			char* key = NULL;
			char* text = NULL;
			char* cipherText = NULL;

			// if not a valid connection, terminate it
			if(clientApproved != 1)
				close(establishedConnectionFD);
			else // valid connection
			{
				// retrieve text
				retrievePackage(&establishedConnectionFD,&text);
				
				// retrieve key
				retrievePackage(&establishedConnectionFD,&key);
				
				// allocate cipherText enough memory based on length of cipher
				cipherText = calloc(sizeof(char)*(strlen(key)+1),sizeof(char)); //+1 accounts for terminating char
				
				// send key, text, and string to hold encoded text
				encodeText(&cipherText,text,key);
				
				// return now encoded text to client
				sendCiphertext(cipherText, &establishedConnectionFD);
			}
			// free up string memory
			free(key);
			free(text);

			close(establishedConnectionFD); // Close the existing socket which is connected to the client
			exit(0);

		}
	}

	close(listenSocketFD);	// close the listening socket
	return 0; 
}

// verifies who is connected (otp_enc, otp_dec)
// returns 1 if handshake was accepted, 0 otherwise
int handshakeVerify(int *identifyMe)
{
	char buffer[5];
	memset(buffer,'\0',sizeof(buffer));

	// receive unique id from client
	int dataRead = recv(*identifyMe,&buffer,sizeof(buffer)-1,0);

	if(dataRead < 0)
		error("Unable to read from socket",1);
	else
	{
		int u_id = atoi(buffer);
		if(u_id != 5512) // check if it matches id for otp_enc
		{
			send(*identifyMe,&handshakeDeny,sizeof(handshakeDeny),0);
			return 0;
		}
		else
		{
			send(*identifyMe,&handshakeAccept,sizeof(handshakeAccept),0);
			return 1;
		}

	}		
	return 0;
}

// Retrieves package from client, storing into the provided char**
// Accepts int* to the established connection, and char** for where to store received file
void retrievePackage(int *estCon, char** receivedFile)
{
	char* totalMsg;
	char tmpBuffer[1024];
	memset(tmpBuffer,'\0',sizeof(tmpBuffer));

	long int totalMsgSize = 200000;
	long int bytesRead = 0;
	int readStat = 1;
	long int totalMsgIter = 0;
	
	// flag for if terminating character is found ('?')
	int endOfMsgReached = 0;

	// allocate proper size
	*receivedFile = calloc(sizeof(char) * totalMsgSize,sizeof(char));	
	
	// while still reading and terminator not found
	while (readStat > 0 && !endOfMsgReached)
	{
		readStat = recv(*estCon, &tmpBuffer, sizeof(tmpBuffer), 0);
		bytesRead += readStat;

		int i;
		for(i = 0; i < 1024; i++)
		{
			if(tmpBuffer[i]== '?')
			{
				tmpBuffer[i] = '\0';
				(*receivedFile)[totalMsgIter] = tmpBuffer[i];
				endOfMsgReached = 1;
				break;
			}

			(*receivedFile)[totalMsgIter] = tmpBuffer[i];
			totalMsgIter += 1;
		}
		memset(tmpBuffer,'\0',sizeof(tmpBuffer));
	}

	FILE *f = fdopen(*estCon,"w+");
	fflush(f);
}

void encodeText(char** cipher, char* plain, char* key)
{

	int i;
	for(i = 0; i < strlen(plain); i++)
	{
		int tmpCipher;
		int tmpPlain;
		int tmpKey;

		if(plain[i] == ' ')
			tmpPlain = 26; //code value for space
		else
		{
			tmpPlain = plain[i] - 65;// convert the ascii integer value to our code (0-25) version
		}

		if(key[i] == ' ')
			tmpKey = 26;
		else
		{
			tmpKey = key[i] - 65;
		}

		tmpCipher = (tmpPlain + tmpKey) % 27;

		if(tmpCipher == 26) //26 is space
			(*cipher)[i] = ' ';
		else
		{
			(*cipher)[i] = tmpCipher + 65;
		}
	}

}

void sendCiphertext(char* cipher, int *estCon)
{
	char* term = "?";
	strcat(cipher,term);
	long int totalSent = 0;
	while(totalSent < strlen(cipher))	
	{
		int sent = 	send(*estCon,cipher, strlen(cipher),0);	
		totalSent += sent;
	}
	
}

/****************************************
 *				catchSIGINT			*	
 *										*
 * Handles SIGINT signal that toggles	* 
 * foreground only mode.				*
 * *************************************/
void catchSIGINT(int signo)
{
	keepListening = 0;	
}


void checkOnTheKids()
{
	int childExitMethod = -5;
	pid_t finished_child = waitpid(-1, &childExitMethod, WNOHANG);
	while(finished_child > 0)
		{
			if(WIFSIGNALED(childExitMethod) != 0)
			{
				int term_signal = WTERMSIG(childExitMethod);
				fprintf(stderr,"\nChild PID %d terminated. Signal: %d\n",finished_child, term_signal);
				fflush(stderr);
			}		

			// continue waitpid()ing until return of < 0
			finished_child = waitpid(-1, &childExitMethod, WNOHANG);
		}

}
