/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};//plain text
	char ciphertext[64] = {0,}; // encrypted text
	int len=64;
	char encryptedkey[64] = {0,}; // encryptedkey in ciphertext.txt

	int decryptedkey =0; // decrypt key
	int encryptkey=0; //encrypt random key
	//RSA
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Init failed ");
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_opensession failed ");
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a =0;
	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	if(argc == 1){// missing '-e'or '-d'
		errx(1, "write '-e' or '-d'\n");
	}else if(strcmp(argv[1],"-e")==0){
		if(argc == 2){
			errx(1, "write file name and algorithm\n");
		}
	}else if(strcmp(argv[1],"-d")==0){
		if(argc == 2){
			errx(1, "write file name\n");
		}
	}
	
	if(strcmp(argv[1],"-e")==0){//Encryption
		if(argc == 3){//Ceaser or RSA X
			printf("write algorithm\n ex) TEEencrypt -e [filename] [Ceaser or RSA]\n");
			
		}
		else if(strcmp(argv[3],"Ceaser")==0){//Ceaser Encryption
			printf("========================Ceaser Encryption========================\n");
			printf("%s\n",argv[2]);
			FILE *file_read = fopen(argv[2],"r");//read file argv[2]
			//argv[2] = *.txt
			if (file_read == NULL)
					{
						printf("READ File FAIL \n");
					}
			fgets(plaintext, sizeof(plaintext), file_read);
			fclose(file_read);

			printf("Ceaser Plaintext : %s\n",plaintext);
			//copy plaintext to op.params[0].tmpref.buffer
			memcpy(op.params[0].tmpref.buffer,plaintext,len);
			//printf("buffer : %s\n",(char*)op.params[0].tmpref.buffer);

			//Call TA, TA_TEEencrypt_CMD_RANDOMKEY_GET
			//Get RANDOMKEY
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
			if (res != TEEC_SUCCESS)//delete possible
				errx(1, "TEEC_InvokeCommand1 failed with code 0x%x origin 0x%x",res, err_origin);
			//memcpy(op.params[0].tmpref.buffer,plaintext,len);
			//printf("buffer : %s\n",(char*)op.params[0].tmpref.buffer);

			//Call TA, TA_TEEencrypt_CMD_ENC_VALUE
			//Get encrypted text
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
				
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand2 failed with code 0x%x origin 0x%x",
					res, err_origin);
			
			//copy op.params[0].tmpref.buffer to ciphertext
			memcpy(ciphertext,op.params[0].tmpref.buffer,len);
			printf("Ciphertext : %s", ciphertext);
			
			//write ciphertext and encryptkey
			//save file, file name : ciphertext.txt
			FILE *file_write = fopen("ciphertext.txt","w");
			fputs(ciphertext, file_write);
			
			//Call TA, TA_TEEencrypt_CMD_RANDOMKEY_ENC
			//Get encrypted randomkey
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC,&op,&err_origin);
			//copy op.params[0].tmpref.buffer to encryptkey
			memcpy(&encryptkey,op.params[0].tmpref.buffer,sizeof(encryptkey));
			
			printf("encryptkey is %d\n", encryptkey);
			fprintf(file_write,"%d\n",encryptkey);
			fclose(file_write);
			printf("==========================================================\n");
		}
		else if(strcmp(argv[3],"RSA")==0){//RSA encrypt
			printf("========================RSA Encryption========================\n");
			//open plaintext file, file name : *.txt
			printf("file name : %s\n",argv[2]);
			FILE *file_read = fopen(argv[2],"r");
			if (file_read == NULL)
					{
						printf("READ File FAIL \n");
					}
			fgets(plaintext, sizeof(plaintext), file_read);
			fclose(file_read);
			printf("RSA Plaintext : %s\n",plaintext);
			//copy plaintext to clear
			memcpy(clear,plaintext,RSA_CIPHER_LEN_1024);
			//set op.paramTypes
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
			op.params[0].tmpref.buffer = clear;
			op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[1].tmpref.buffer = ciph;
			op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;

			printf("clear : %s\n",clear);//RSA plaintext
			//printf("ciph : %s\n", ciph);
			
			//Call TA, TA_RSA_CMD_GENKEYS
			// generated rsa key
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_GENKEYS, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
			printf("\n=========== Keys already generated. ==========\n");
			
			printf("\n============ RSA ENCRYPT CA SIDE ============\n");
				
			//Call TA, TA_RSA_CMD_ENCRYPT
			// encrypt plaintext using rsa
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT,
						 &op,&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
					res, err_origin);
			//print ciphertext
			printf("\nThe text sent was encrypted: %s\n", ciph);
			
			//save ciphertext
			FILE *file_write = fopen("RSA_Ciphertext.txt", "w");
			fputs(ciph, file_write); 
			fclose(file_write);

			//***************check RSA********************
			//printf("\n============ RSA DECRYPT CA SIDE ============\n");

			//op.params[0].tmpref.buffer = ciph;
			//op.params[0].tmpref.size = RSA_CIPHER_LEN_1024;
			//op.params[1].tmpref.buffer = clear;
			//op.params[1].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			
			//printf("ciph : %s\n", ciph);
			//printf("clear : %s\n",clear);

			//res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_DECRYPT, &op, &err_origin);
			//if (res != TEEC_SUCCESS)
			//	errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_DECRYPT) failed 0x%x origin 0x%x\n",
			//		res, err_origin);
			//printf("\nThe text sent was decrypted: %s\n", (char *)op.params[1].tmpref.buffer);
		}
		else{
			printf("3rd argument should 'Ceaser' or 'RSA'\n");
		}
	}
	else if(strcmp(argv[1],"-d")==0){
		//read ciphertext.txt file 
		FILE *file_read_ceasar = fopen(argv[2],"r");
			if (strcmp(argv[2],"ciphertext.txt")!=0)//file name must be ciphertext.txt
				errx(1, "decryption file name must be 'ciphertext.txt'\n");
		//first line : ciphertext
		fgets(ciphertext, sizeof(ciphertext), file_read_ceasar);
		printf("========================Ceaser Decryption========================\n");
		printf("Ciphertext : %s\n", ciphertext);
		//second line : encryptedkey
		fgets(encryptedkey, sizeof(encryptedkey), file_read_ceasar);
		printf("encryptedkey : %s\n", encryptedkey);
		fclose(file_read_ceasar);
		
		
		decryptedkey = atoi(encryptedkey);//change type string to int
		//printf("decryptedkey(atoi) : %d\n", decryptedkey);

		//set op.params[1].value.a
		op.params[1].value.a = decryptedkey;
		//printf("op.params[1].value.a : %d\n", op.params[1].value.a);

		//copy ciphertext to op.params[0].tmpref.buffer
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		//printf("encryptkey : %d\n", op.params[1].value.a);
		//printf("Ciphertext : %s\n", (char*)op.params[0].tmpref.buffer);

		//Call TA, TA_TEEencrypt_CMD_DEC_VALUE
		//get decryption ciphertext
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
						 &err_origin);
		if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
		
		//copy op.params[0].tmpref.buffer to plaintext
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Decryption ciphertext : %s", plaintext);
		
		//save Decryption ciphertext
		FILE *file_write_plain = fopen("Decryptiontext.txt","w");
		fputs(plaintext, file_write_plain);
		fprintf(file_write_plain, "%d\n",op.params[1].value.a);
		//printf("decrypted random key %d\n",op.params[1].value.a);
		printf("===========================================================\n");
		fclose(file_write_plain);
	}
	else{
	printf("write '-e' or '-d' \n");
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
