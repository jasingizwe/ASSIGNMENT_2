/*
 * blockchain_mining.c
 * 
 * Blockchain Mining Simulation with Proof of Work
 * Pure C SHA-256 implementation (no external libraries)
 *
 * Tasks:
 * - Define a basic blockchain structure
 * - Proof-of-Work mining algorithm
 * - Add blocks and adjust difficulty
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* ------------------ Simple SHA-256 Implementation ------------------ */
/* Credit: Public domain implementation by Brad Conte (https://github.com/B-Con/crypto-algorithms) */

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTLEFT(a,b) ((a << b) | (a >> (32-b)))
#define ROTRIGHT(a,b) ((a >> b) | (a << (32-b)))
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ (x >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ (x >> 10))

static const uint32_t k[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i=0,j=0;i<16;i++,j+=4)
        m[i] = (data[j]<<24) | (data[j+1]<<16) | (data[j+2]<<8) | (data[j+3]);
    for (;i<64;i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (i=0;i<64;i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen=0; ctx->bitlen=0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i=0;i<len;i++) {
        ctx->data[ctx->datalen]=data[i];
        ctx->datalen++;
        if (ctx->datalen==64) {
            sha256_transform(ctx,ctx->data);
            ctx->bitlen+=512;
            ctx->datalen=0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx,uint8_t hash[]) {
    uint32_t i=ctx->datalen;
    if (ctx->datalen<56) {
        ctx->data[i++]=0x80;
        while(i<56) ctx->data[i++]=0x00;
    } else {
        ctx->data[i++]=0x80;
        while(i<64) ctx->data[i++]=0x00;
        sha256_transform(ctx,ctx->data);
        memset(ctx->data,0,56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63]=(uint8_t)(ctx->bitlen);
    ctx->data[62]=(uint8_t)(ctx->bitlen>>8);
    ctx->data[61]=(uint8_t)(ctx->bitlen>>16);
    ctx->data[60]=(uint8_t)(ctx->bitlen>>24);
    ctx->data[59]=(uint8_t)(ctx->bitlen>>32);
    ctx->data[58]=(uint8_t)(ctx->bitlen>>40);
    ctx->data[57]=(uint8_t)(ctx->bitlen>>48);
    ctx->data[56]=(uint8_t)(ctx->bitlen>>56);
    sha256_transform(ctx,ctx->data);

    for(i=0;i<8;i++) {
        hash[i*4]   = (ctx->state[i]>>24) & 0xff;
        hash[i*4+1] = (ctx->state[i]>>16) & 0xff;
        hash[i*4+2] = (ctx->state[i]>>8) & 0xff;
        hash[i*4+3] = ctx->state[i] & 0xff;
    }
}

/* Helper function: compute SHA-256 of a string and return hex string */
void computeSHA256String(char *str, char output[65]) {
    SHA256_CTX ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t*)str, strlen(str));
    sha256_final(&ctx, hash);

    for(int i=0;i<32;i++)
        sprintf(output+i*2,"%02x",hash[i]);
    output[64]='\0';
}

/* ------------------ Blockchain Structures ------------------ */

typedef struct Block {
    int index;
    time_t timestamp;
    char transactions[256];
    char previousHash[65];
    char hash[65];
    int nonce;
    struct Block *next;
} Block;

/* ------------------ Proof of Work Functions ------------------ */

void calculateHash(Block *block, char output[65]) {
    char input[512];
    sprintf(input,"%d%ld%s%s%d",block->index,block->timestamp,block->transactions,block->previousHash,block->nonce);
    computeSHA256String(input,output);
}

void proofOfWork(Block *block,int difficulty) {
    char target[65];
    for(int i=0;i<difficulty;i++) target[i]='0';
    target[difficulty]='\0';

    do {
        block->nonce++;
        calculateHash(block,block->hash);
    } while(strncmp(block->hash,target,difficulty)!=0);
}

/* ------------------ Block Creation ------------------ */

Block* createBlock(int index,char *transactions,char *prevHash,int difficulty) {
    Block *block=(Block*)malloc(sizeof(Block));
    block->index=index;
    block->timestamp=time(NULL);
    strcpy(block->transactions,transactions);
    strcpy(block->previousHash,prevHash);
    block->nonce=0;
    block->next=NULL;

    printf("Mining block %d...\n",index);
    proofOfWork(block,difficulty);
    printf("Block %d mined! Hash: %s\n\n",index,block->hash);
    return block;
}

void addBlock(Block **chain,char *transactions,int difficulty) {
    if(*chain==NULL) {
        *chain=createBlock(0,transactions,"0",difficulty);
    } else {
        Block *current=*chain;
        while(current->next!=NULL) current=current->next;
        Block *newBlock=createBlock(current->index+1,transactions,current->hash,difficulty);
        current->next=newBlock;
    }
}

/* ------------------ Simulation Function ------------------ */

void simulateMining(int difficulty) {
    Block *chain=NULL;
    printf("=== Simulating Difficulty %d ===\n",difficulty);
    clock_t start=clock();

    addBlock(&chain,"Alice pays Bob 5 BTC",difficulty);
    addBlock(&chain,"Bob pays Charlie 2 BTC",difficulty);

    clock_t end=clock();
    double time_taken=((double)(end-start))/CLOCKS_PER_SEC;
    printf("Time taken with difficulty %d: %.2f seconds\n\n",difficulty,time_taken);
}

/* ------------------ MAIN ------------------ */

int main() {
    simulateMining(3);
    simulateMining(4);
    return 0;
}
