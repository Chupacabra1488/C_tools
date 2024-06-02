#include "lobo.h"
#include <gcrypt.h>

#define ENCR 1
#define DECR 0

void my_crypt(int encdec,const char* password,const char* salt,const char* test);


int main(int argc,char** argv)
{
    if(argc!=4)
    {
        fprintf(stderr,"Usage <%s> <-e | -d> <password> <salt>\n",argv[0]);
        exit(EXIT_FAILURE);
    }

    int encdec=ENCR;
    char line[1024];

    printf("Enter text:\n");
    fgets(line,sizeof(line),stdin);

    if(!strcmp(argv[1],"-d"))
    {
        int i=0;
        char a[3]={"00"};
        for(i;i<strlen(line);i+=2)
        {
            sprintf(a,"%c%c",line[i],line[i+1]);
            line[i/2]=strtol(a,NULL,16);
        }
        line[i/2-1]='\0';
        encdec=DECR;
    }

    my_crypt(encdec,argv[2],argv[3],line);

    return 0;
}

void my_crypt(int encdec,const char* password,const char* salt,const char* text)
{
    gcry_error_t gcry_error;
    gcry_cipher_hd_t hd;
    size_t i;

    size_t pass_len=strlen(password);
    size_t salt_len=strlen(salt);
    size_t text_len=strlen(text)+encdec;
    char* out_buffer=(char*)malloc(text_len);

    printf("%scryption...\n",encdec?"En":"De");
    printf("pass_len = %ld\n",pass_len);
    printf("salt_len = %ld\n",salt_len);
    printf("text_len = %ld\n",text_len);
    printf("\tpass = %s\n",password);
    printf("\tsalt = %s\n",salt);
    printf("\ttext = %s\n",encdec?text:"<null>");

    gcry_error=gcry_cipher_open(&hd,GCRY_CIPHER_AES128,GCRY_CIPHER_MODE_CBC,
    GCRY_CIPHER_CBC_CTS);
    if(gcry_error)
    {
        fprintf(stderr,"gcry_cipher_open error: %s / %s\n",
        gcry_strsource(gcry_error),gcry_strerror(gcry_error));
        exit(EXIT_FAILURE);
    }

    gcry_error=gcry_cipher_setkey(hd,password,pass_len);
    if(gcry_error)
    {
        fprintf(stderr,"Error of gcry_cipher_setkey: %s / %s\n",
        gcry_strsource(gcry_error),gcry_strerror(gcry_error));
        exit(EXIT_FAILURE);
    }

    gcry_error=gcry_cipher_setiv(hd,salt,salt_len);
    if(gcry_error)
    {
        fprintf(stderr,"Error of gcry_cipher_setiv: %s / %s\n",
        gcry_strsource(gcry_error),gcry_strerror(gcry_error));
        exit(EXIT_FAILURE);
    }

    switch(encdec)
    {
        case ENCR:
            gcry_error=gcry_cipher_encrypt(hd,out_buffer,text_len,text,text_len);
            break;
        case DECR:
            gcry_error=gcry_cipher_decrypt(hd,out_buffer,text_len,text,text_len);
            break;
        if(gcry_error)
        {
            fprintf(stderr,"Error of gcry_cipher_encrypt/decrypt: %s / %s\n",
            gcry_strsource(gcry_error),gcry_strerror(gcry_error));
            exit(EXIT_FAILURE);
        }
    }

    switch(encdec)
    {
        case ENCR:
            printf("Encrypted text = %s\n",out_buffer);
            break;
        case DECR:
            printf("Original text = %s\n",out_buffer);
            break;
    }

    gcry_cipher_close(hd);
    free(out_buffer);
}