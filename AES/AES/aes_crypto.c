#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#define BUFFER_SIZE 4096
#define HASH_SIZE 128

int main(int argc,char** argv)
{
    const char* file_name="test_file.txt";
    int plain_fd;
    plain_fd=open(file_name,O_RDONLY);
    if(plain_fd==-1)
    {
        fprintf(stderr,"Error of open calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    char plain_buffer[BUFFER_SIZE];
    memset(plain_buffer,0,BUFFER_SIZE);
    ssize_t num_bytes;
    num_bytes=read(plain_fd,plain_buffer,BUFFER_SIZE);
    if(num_bytes==-1)
    {
        fprintf(stderr,"Error of read calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    AES_KEY aes_encrypt_key;
    AES_KEY aes_decrypt_key;
    if(argc!=2)
    {
        fprintf(stderr,"Enter your password.\n");
        exit(EXIT_FAILURE);
    }
    const unsigned char* user_key=(unsigned char*)argv[1];
    const int num_of_bits=128;
    AES_set_encrypt_key(user_key,num_of_bits,&aes_encrypt_key);
    AES_set_decrypt_key(user_key,num_of_bits,&aes_decrypt_key);

    unsigned char encrypt_buffer[BUFFER_SIZE];
    memset(encrypt_buffer,0,BUFFER_SIZE);

    unsigned int data_offset=0;
    int num_of_blocks;
    num_of_blocks=num_bytes/16;
    if(num_bytes%16) num_of_blocks++;

    for(size_t i=0;i<num_of_blocks;++i)
    {
        AES_encrypt((unsigned char*)plain_buffer+data_offset,
        encrypt_buffer+data_offset,&aes_encrypt_key);
        data_offset+=16;
    }
    
    unsigned char decrypt_buffer[BUFFER_SIZE];
    memset(decrypt_buffer,0,BUFFER_SIZE);
    data_offset=0;

    for(size_t i=0;i<num_of_blocks;++i)
    {
        AES_decrypt(encrypt_buffer+data_offset,
        decrypt_buffer+data_offset,&aes_decrypt_key);
        data_offset+=16;
    }
    
    unsigned char plain_hash[HASH_SIZE];
    unsigned char decrypt_hash[HASH_SIZE];
    memset(plain_hash,0,HASH_SIZE);
    memset(decrypt_hash,0,HASH_SIZE);

    MD5((unsigned char*)plain_buffer,strlen(plain_buffer),plain_hash);
    MD5((unsigned char*)decrypt_buffer,strlen(decrypt_buffer),decrypt_hash);

    printf("Plain hash: \n\t");
    for(size_t i=0;i<strlen(plain_hash);++i)
    {
        printf("%02x",plain_hash[i]);
    }
    printf("\n");

    printf("Decrypt hash: \n\t");
    for(size_t i=0;i<strlen(decrypt_hash);++i)
    {
        printf("%02x",decrypt_hash[i]);
    }
    printf("\n%ld\n",strlen(plain_hash));

    return 0;
}