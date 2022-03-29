/* 
**  ledger_seed.cl
**  Writen by Arran Holmes
**  Uses crypto primitives from Hashcat
*/

// Enables printing of intermediate values
#define DEBUG 



// Buffer struts to exchange data with host (Python)
typedef struct {
    u32 found;
	u32 index;
} resbuf;

typedef struct {
    u32 length;
	uchar buffer[100];
} seedbuf;

typedef struct {
    u32 length;
    uchar buffer[32]; 
} inbuf;



// ***************
//
// Adapted from inc_ecc_secp256k1.cl part of Hashcat
// Adds together two u32[9] values to each other.
// Used to perform a limted mod fuction.
//
// ***************
void sub_32 (u32 *r, const u32 *a, const u32 *b)
{
  u32 c = 0; // carry/borrow
  for (int i = 8; i >=0; i--)
  {
    const u32 diff = a[i] - b[i] - c;
    if (diff != a[i]) c = (diff > a[i]);
    r[i] = diff;
  }
	// ignore c
}


// ***************
//
// Adapted from inc_ecc_secp256k1.cl part of Hashcat
// Adds together two u32[8] values together with a modulus curve order.
// (aa + bb) % n
// results is u32[9] to cover the carry
//
// ***************
void add_mod_32 (u32 *r, const u32 *aa, const u32 *bb){
  u32 c = 0; // carry/borrow
  u32 n[9];
  
  n[0] = 0;
  n[1] = SECP256K1_N7;
  n[2] = SECP256K1_N6;
  n[3] = SECP256K1_N5;
  n[4] = SECP256K1_N4;
  n[5] = SECP256K1_N3;
  n[6] = SECP256K1_N2;
  n[7] = SECP256K1_N1;
  n[8] = SECP256K1_N0;
  
	
  for (int i = 7; i >= 0 ; i--)
  {
    const u32 t = aa[i] + bb[i] + c;
    if (t != aa[i]) c = (t < aa[i]);
    r[i+1] = t;
  } 
  r[0] = c;
 
  // check if bigger than n (curve order) if it is take the modulus (in 
this case just subtract n)
  u32 mod = 1;
  if (c == 0)
  {
    for (int i = 8; i >= 0; i--)
    {
      if (r[i] < n[i])
      {
        mod = 0;
        break; // or return ! (check if faster)
      }
      if (r[i] > n[i]) break;
    }
  }
  
  if (mod == 1)
  {
	sub_32 (r, r, n);
  }
 }
 


// ***************
//
// Main kernel function
// calculates the extended public key from a seed phrase and password.
// parts of this code were adapted from m12000-pure.cl part of Hashcat
//
// ***************
__kernel void just_seed(__global const inbuf * passwords, __global const 
seedbuf * sbuf, __global resbuf * results) {
	u32 debug = 1;        // enable or disable debugging DEBUG must 
also be defined.
	u32 debug_idx = 0;    // queue item to debug
	
	ulong idx = get_global_id(0);
	
	
	// Copy the seed word from global memory - is this faster/needed?
	uchar seedword[128]={0};
	u32 seedword_length = sbuf[0].length;
	
	#if defined DEBUG
	if(idx==debug_idx){
		printf("\nidx: %d\nseedword_length: %d \n",idx, 
seedword_length);
	}
	#endif
	
	for(u32 x=0;x!=seedword_length;x++){
		seedword[x] = sbuf->buffer[x];
	}
	
	
	#if defined DEBUG
		if(idx==debug_idx){
		printf("Seed Phrase: ");
		for(u32 x=0;x!=seedword_length;x++){
			printf("%c",seedword[x]);
		}
	}
	#endif
	
	// Copy the password out of global memory, this is used as the 
salt  "mnemoic"+password+(u32)1
	u32 password_length = passwords[idx].length;
	uchar salt[128]={0};
	salt[0] = 'm';
	salt[1] = 'n';
	salt[2] = 'e';
	salt[3] = 'm';
	salt[4] = 'o';
	salt[5] = 'n';
	salt[6] = 'i';
	salt[7] = 'c';	
	u32 count=0;
	for(;count!=password_length;count++){
		salt[8+count] = passwords[idx].buffer[count];
	}
	salt[count+8] = 0;	
	salt[count+9] = 0;	
	salt[count+10] = 0;	
	salt[count+11] = 1;
	u32 salt_length = password_length+12;
	
	
	#if defined DEBUG
		if(idx==debug_idx){
		printf("\nsalt_length: %d",salt_length);
		printf("\nPassword: ");
		for(u32 x=0;x!=salt_length;x++){
			printf("%x ",salt[x]);
		}
	}
	#endif
	
	// seedword and salt must be 128 bytes 
	u64 seed[16] = { 0 };
	sha512_hmac_ctx_t ctx;
	sha512_hmac_init_swap (&ctx, (u32 *)seedword, seedword_length);  
// len is only <= or > 128
	sha512_hmac_update_swap (&ctx, (u32 *)salt, salt_length);
	sha512_hmac_final (&ctx);

	seed[0] ^= ctx.opad.h[0];
	seed[1] ^= ctx.opad.h[1];
	seed[2] ^= ctx.opad.h[2];
	seed[3] ^= ctx.opad.h[3];
	seed[4] ^= ctx.opad.h[4];
	seed[5] ^= ctx.opad.h[5];
	seed[6] ^= ctx.opad.h[6];
	seed[7] ^= ctx.opad.h[7];


// pbkdf2-hmac-sha256(2048)

	u64 temp[32]= {0};
	for(u32 l=1;l!=2048;l++){

		temp[0] = hc_swap64_S  (ctx.opad.h[0]);
		temp[1] = hc_swap64_S  (ctx.opad.h[1]);
		temp[2] = hc_swap64_S  (ctx.opad.h[2]);
		temp[3] = hc_swap64_S  (ctx.opad.h[3]);
		temp[4] = hc_swap64_S  (ctx.opad.h[4]);
		temp[5] = hc_swap64_S  (ctx.opad.h[5]);
		temp[6] = hc_swap64_S  (ctx.opad.h[6]);
		temp[7] = hc_swap64_S  (ctx.opad.h[7]);

		sha512_hmac_init_swap (&ctx, (u32 *)seedword, 
seedword_length);
		sha512_hmac_update_swap (&ctx, (u32 *)temp, 64);
		sha512_hmac_final (&ctx);

		seed[0] ^= ctx.opad.h[0];
		seed[1] ^= ctx.opad.h[1];
		seed[2] ^= ctx.opad.h[2];
		seed[3] ^= ctx.opad.h[3];
		seed[4] ^= ctx.opad.h[4];
		seed[5] ^= ctx.opad.h[5];
		seed[6] ^= ctx.opad.h[6];
		seed[7] ^= ctx.opad.h[7];
	}
	
	#if defined DEBUG
		if(idx==debug_idx){
			printf("\nMaster Seed: ");
			for(u32 x=0;x!=8;x++){
				printf("%00000000llx ",seed[x]);
			}
		}
	#endif


// Generate master seed (BIP32)
	sha512_hmac_ctx_t ctx2;
	uchar salt2[128] ={0};
	salt2[0] = 'B';
	salt2[1] = 'i';
	salt2[2] = 't';
	salt2[3] = 'c';
	salt2[4] = 'o';
	salt2[5] = 'i';
	salt2[6] = 'n';
	salt2[7] = ' ';	
	salt2[8] = 's';	
	salt2[9] = 'e';	
	salt2[10] = 'e';	
	salt2[11] = 'd';
	
	#if defined DEBUG
		if(idx==debug_idx){
			printf("\nsalt2: ");
			for(u32 x=0;x!=12;x++){
				printf("%x ",salt2[x]);
			}
		}
	#endif
	
	u64 temp2[64]={0};
	temp2[0] = hc_swap64_S  (seed[0]);
	temp2[1] = hc_swap64_S  (seed[1]);
	temp2[2] = hc_swap64_S  (seed[2]);
	temp2[3] = hc_swap64_S  (seed[3]);
	temp2[4] = hc_swap64_S  (seed[4]);
	temp2[5] = hc_swap64_S  (seed[5]);
	temp2[6] = hc_swap64_S  (seed[6]);
	temp2[7] = hc_swap64_S  (seed[7]);
	
	#if defined DEBUG
		if(idx==debug_idx){
			printf("\ntemp2: ");
			for(u32 x=0;x!=8;x++){
				printf("%00000000llx ",temp2[x]);
			}
		}
	#endif
	
	
	sha512_hmac_init_swap (&ctx2, (u32 *)salt2, 12);
	sha512_hmac_update_swap (&ctx2, (u32 *)temp2, 64);
	sha512_hmac_final (&ctx2);
	
	#if defined DEBUG
		if(idx==debug_idx){
			printf("\nRoot Private Key: ");
			for(u32 x=0;x!=8;x++){
				printf("%00000000llx ",ctx2.opad.h[x]);
			}
		}
	#endif


	// First 32 bytes of ctx.opad.h are the Private Key, last 32 bytes 
are the Chain Code.

	
	u64 out[8]={0};
	// key
	out[0] = ctx2.opad.h[0];
	out[1] = ctx2.opad.h[1];
	out[2] = ctx2.opad.h[2];
	out[3] = ctx2.opad.h[3];


	// chain code
	seed[0] =  hc_swap64_S (ctx2.opad.h[4]);
	seed[1] =  hc_swap64_S (ctx2.opad.h[5]);
	seed[2] =  hc_swap64_S (ctx2.opad.h[6]);
	seed[3] =  hc_swap64_S (ctx2.opad.h[7]);
	seed[4] = 0;
	seed[5] = 0;
	seed[6] = 0;
	seed[7] = 0;

	u32 a[16]={0};
	a[ 0] = h32_from_64_S (out[0]);
	a[ 1] = l32_from_64_S (out[0]);
	a[ 2] = h32_from_64_S (out[1]);
	a[ 3] = l32_from_64_S (out[1]);
	a[ 4] = h32_from_64_S (out[2]);
	a[ 5] = l32_from_64_S (out[2]);
	a[ 6] = h32_from_64_S (out[3]);
	a[ 7] = l32_from_64_S (out[3]);


// ************
// perform a % n where n is the secp256k1 curve order
// Adapted from inc_ecc_secp256k1.cl part of Hashcat
// ************

	u32 n[8];
	n[0] = SECP256K1_N7;
	n[1] = SECP256K1_N6;
	n[2] = SECP256K1_N5;
	n[3] = SECP256K1_N4;
	n[4] = SECP256K1_N3;
	n[5] = SECP256K1_N2;
	n[6] = SECP256K1_N1;
	n[7] = SECP256K1_N0;
  
	u32 mod = 1;
    for (u32 i = 0; i <= 7; i++)
    {
      if (a[i] < n[i])
      {
        mod = 0;
        break; // or return ! (check if faster)
      }
      if (a[i] > n[i]) break;
    }
	if (mod){
		sub_32(a,a,n);
	}
	
// end a % n

	u32 tweak[8];
	tweak[0] = a[7];
	tweak[1] = a[6];
	tweak[2] = a[5];
	tweak[3] = a[4];
	tweak[4] = a[3];
	tweak[5] = a[2];
	tweak[6] = a[1];
	tweak[7] = a[0];

	secp256k1_t coords;
	set_precomputed_basepoint_g (&coords);
	u32 pubkey[64] = { 0 };  // pubkey is only 32+1 but we need 128 
bytes for the hash function comming up
	point_mul (pubkey, tweak, &coords);

	#if defined DEBUG
		if(idx==debug_idx){
			pubkey[9] = 0; // child key index
			printf("\nRoot Public Key: ");
			for(u32 x=0;x!=9;x++){
				printf("%08llx ",pubkey[x]);
			}
		}
	#endif

	//128 byte blocks
	sha512_hmac_init_swap (&ctx, (u32 *)seed, 32);
	sha512_hmac_update (&ctx, (u32 *)pubkey, 37);
	sha512_hmac_final (&ctx);
	
	#if defined DEBUG
		if(idx==debug_idx){ 
			printf("\nhmac: ");
			for(u32 x=0;x!=8;x++){
				printf("%016llx ",ctx.opad.h[x]);
			}
		}
	#endif
	
	u32 y[8]={0};
	y[ 0] = h32_from_64_S (ctx.opad.h[0]);
	y[ 1] = l32_from_64_S (ctx.opad.h[0]);
	y[ 2] = h32_from_64_S (ctx.opad.h[1]);
	y[ 3] = l32_from_64_S (ctx.opad.h[1]);
	y[ 4] = h32_from_64_S (ctx.opad.h[2]);
	y[ 5] = l32_from_64_S (ctx.opad.h[2]);
	y[ 6] = h32_from_64_S (ctx.opad.h[3]);
	y[ 7] = l32_from_64_S (ctx.opad.h[3]);


	u32 result[9]={0};
	add_mod_32(result, y, a); 		// result = (y + a) % n 
where n is the secp256k1 curve order
		
		
	#if defined DEBUG
		if(idx==debug_idx){
			printf("\nchild private key: ");
			for(u32 x=0;x!=9;x++){
				printf("%08x ",result[x]);
			}
		}
	#endif
	
	tweak[0] = result[8];
	tweak[1] = result[7];
	tweak[2] = result[6];
	tweak[3] = result[5];
	tweak[4] = result[4];
	tweak[5] = result[3];
	tweak[6] = result[2];
	tweak[7] = result[1];
	
	
	u32 pubkey2[34] = { 0 };  // pubkey is only 32+1 but we need 128 
for the hash function comming up
	//set_precomputed_basepoint_g (&coords);
	point_mul (pubkey2, tweak, &coords);
	
	#if defined DEBUG
		if(idx==debug_idx){
			printf("\nExtended Public Key: ");
			for(u32 x=0;x!=9;x++){
				printf("%08llx ",pubkey2[x]);
			}
		}
	#endif

	if(pubkey2[0] == 0x03e37332){
		printf("\nFound Password\n");
		results->found=1;
		results->index=idx;
		return;
	}
}

#ledger m/84'/0'/0'
