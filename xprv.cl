/** 
**		xprv.cl
**		Electrum encrypted private key password brute forcing tool
**		Written by Arran Holmes  40454196
**		
**		Uses crypto primitives from Hashcat
**		Achieves a rate of about 25,000,000 passwords per second
**		on an Nvidia RTX 3090
**/

//#define DEBUG_IDX 0

typedef struct {
    u32 found;
	u32 index;
} resbuf;

typedef struct {
    u32 buffer[4]; // 16 bytes
} ivbuf;

typedef struct {
    u32 buffer[4]; // 16 bytes
} ctbuf;

typedef struct {
    u32 length;    // in bytes 4 bytes
    u32 buffer[7]; // 28 character max password length
} inbuf;

typedef struct {
    u32 buffer[8];
} outbuf;


// some of this code is adapted from m01400_a0-pure.cl part of Hashcat

__kernel void hash_main(__global const inbuf * inbuffer, __global resbuf * 
results, __global const ivbuf * ivbuffer, __global const ctbuf * ctbuffer)
{
	outbuf outbuffer;
    u32 idx = get_global_id(0);

	u32 tmpbuffer[16]={0};
	u32 tmpbuffer_length=inbuffer[idx].length;
	
	for (u32 x=0; x!=7; x++){
		tmpbuffer[x] = inbuffer[idx].buffer[x];
	}
	#if defined DEBUG_IDX
		if(idx==DEBUG_IDX){
			printf("idx: %i len: %d password: 
%08x%08x%08x%08x%08x%08x%08x%08x\n", idx, tmpbuffer_length, tmpbuffer[0], 
tmpbuffer[1], tmpbuffer[2], tmpbuffer[3], tmpbuffer[4], tmpbuffer[5], 
tmpbuffer[6], tmpbuffer[7]);
		}
	#endif
	
	sha256_ctx_t ctx;
	sha256_init (&ctx);
	sha256_update_swap(&ctx,tmpbuffer,tmpbuffer_length);  // length in 
bytes
	sha256_final(&ctx);
	#if defined DEBUG_IDX
		if(idx==DEBUG_IDX){
			printf("idx: %i sha(256): %08x %08x %08x %08x %08x 
%08x %08x %08x\n", idx, ctx.h[0], ctx.h[1], ctx.h[2], ctx.h[3], ctx.h[4], 
ctx.h[5], ctx.h[6], ctx.h[7]);
		}
	#endif
	
	u32 tmpbuffer2[16]={0};
	for (u32 x=0; x!=8; x++){
		tmpbuffer2[x] = ctx.h[x];
	}
	
	sha256_ctx_t ctx2;
	sha256_init(&ctx2);
	sha256_update(&ctx2,tmpbuffer2,32);  // length in bytes
	sha256_final(&ctx2);
	#if defined DEBUG_IDX
		if(idx==DEBUG_IDX){
			printf("idx: %i sha(256): %08x %08x %08x %08x %08x 
%08x %08x %08x\n", idx, ctx2.h[0], ctx2.h[1], ctx2.h[2], ctx2.h[3], 
ctx2.h[4], tx2.h[5], ctx2.h[6], ctx2.h[7]);
		}
	#endif
	
	uint iv[4];
	iv[0] = hc_swap32_S (ivbuffer[0].buffer[0]);
	iv[1] = hc_swap32_S (ivbuffer[0].buffer[1]);
	iv[2] = hc_swap32_S (ivbuffer[0].buffer[2]);
	iv[3] = hc_swap32_S (ivbuffer[0].buffer[3]);
	#if defined DEBUG_IDX
		if(idx==DEBUG_IDX){
			printf("idx: %i IV: %08x%08x%08x%08x\n", idx, 
iv[0], iv[1], iv[2], iv[3]);
		}
	#endif
	
	uint ks[60]; // expanded key
	AES256_set_decrypt_key (ks, ctx2.h, te0, te1, te2, te3, td0, td1, 
td2, td3);
	
	uint ct[4];
    	ct[0] = hc_swap32_S (ctbuffer[0].buffer[0]);
    	ct[1] = hc_swap32_S (ctbuffer[0].buffer[1]);
    	ct[2] = hc_swap32_S (ctbuffer[0].buffer[2]);
    	ct[3] = hc_swap32_S (ctbuffer[0].buffer[3]);
	#if defined DEBUG_IDX
		if(idx==DEBUG_IDX){
			printf("idx: %i cyphertext: %08x%08x%08x%08x\n", 
idx, ct[0], ct[1], ct[2], ct[3]);
		}
	#endif
	
	u32 pt[4];
	AES256_decrypt (ks, ct, pt, td0, td1, td2, td3, td4);
	
	// needed for AES-256-CBC
	pt[0] = pt[0] ^ iv[0];
	pt[1] = pt[1] ^ iv[1];
	pt[2] = pt[2] ^ iv[2];
	pt[3] = pt[3] ^ iv[3];
	#if defined DEBUG_IDX
		if(idx==DEBUG_IDX){
			printf("idx: %i Decrypted: %08x %08x %08x %08x\n", 
idx, pt[0], pt[1], pt[2], pt[3]);
		}
	#endif
	
	// Produces a few false positives.
	// Should check for more than just xpub/ypub/zpub.
	// However this validation will be left to Python
	// where blockchain API calls can be made for balance etc
	switch(pt[0])
	{
		case 0x78707276: // xpub
			break;
			
		case 0x79707276: // ypub
			break;
		
		case 0x7a707276: // zpub
			break;
			
		default:  // not a candidate
			return;
	}
	
	// Need to allow for multiple candidates in a password block.
	// Could use an array of u32, but how many are enough for a 
10,000,000 password block?
	// With global shared memory are there race condition issues?
	//results->result[results->found];
	//results->found+=1;
	//return;

	results->found=1;
	results->index=idx;
	return;
}


/*
Test Vector
key:  1fa75c5dcd1855f0644d55adc8f2852ce582683b14bcd917bac9e20737dcce9b
iv:  a028565b37da9263b3f04e2d25ec1c50
ciphertext:  25b793b8b028ddeb66814edafaa817e3
plaintext:  7a70727641646535444c594461785441

AES all inputs zero, result
67671ce1fa91ddeb0f8fbbb366b531b
*/


