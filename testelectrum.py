#
#  testElectrum.py
#  Written by Arran Holmes 40454196
#
import gzip
import pyopencl as cl
import numpy as np
import os
import time
import base64
import mmap
import pyopencl as cl
import lzma
os.environ["PYOPENCL_CTX"] = "0" // use first openCL device

print("Electrum encrypted priave key brtute forcing tool");

# const definitions
encrypted_zPrv = 
b"oChWWzfakmOz8E4tJewcUCW3k7iwKN3rZoFO2vqoF+MxRPP0VQRIPsMeIwdG9aLWpD9kp
    
f7O0jidsmlTUXKXLiStfmuCFFNktzBpcXnFZ7Sp9lULEOGgwNGJo90B61jf9B63qj1dsyL+
    FGUetgGc7cO6JU6m7bsEVN9YC9hQNlE="
password = "goodpassword"
#encrypted_zPrv = 
b"zoTuL7SQr3Kkdyn8MygH6+ONqw6LLYxwpXJXs8Mq8eVr5W2nZM0LUhb5FNDEu7JHY3DD
    
dIy8TfwSypHTh0osmmIGihj0sLFvpiqJALtWiv4uZ2kcGUgPqUdMsrKUKzAmKhZUyGUChOGv5JN
    bNUICNa1kcSyz6bNV1MP8lfCKvk0="
#password = "password"


data_bytes = bytes(base64.b64decode(encrypted_zPrv))
iv, cyphertext = data_bytes[:16], data_bytes[16:32]
ctx = cl.create_some_context()
queue = cl.CommandQueue(ctx)
wordSize = 4 #bytes
passwordBlockSize = 10000000
print_debug = True
first_time = True


# Compile the Kernel
start = time.time()
code=""
files_to_compile = ["inc_vendor.h","inc_types.h","inc_platform.h", 
"inc_common.h","inc_cipher_aes.h", "inc_hash_sha256.h", "inc_platform.cl", 
"inc_common.cl", "inc_cipher_aes.cl", "inc_hash_sha256.cl", "xprv.cl"]
for file in files_to_compile:
    f =open(file,'r')
    code += f.read()
    code += "\n"

# Compile the OpenCL code
print("Compiling OpenCL kernel, this may take several minutes first time")
prg = cl.Program(ctx, code).build()
end = time.time()
if(print_debug): print("Compiling kernal completed in ",end-start, " 
seconds")

start = time.time()
# load the (pre-formatted) dictionary
f = open("dictionary.dict", mode="rb")
dictonary = mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ)
totalPass = int(dictonary.size()/32)

print("Dictionary size: ", totalPass)


tstart = time.time()
while(True):
    start = time.time()
    buf = dictonary.read(32* passwordBlockSize)
    if not buf:  break
    NoPasswords = int(len(buf)/32)
    end = time.time()
    if(print_debug): print("Loaded ",NoPasswords," passwords in 
",end-start, " seconds")   


    start = time.time()
    b = np.zeros( 2, dtype=np.int32)
    #buf = np.frombuffer(buf, dtype=np.int32)
    if first_time:
        IV = np.frombuffer(iv, dtype=np.int32)
        CT = np.frombuffer(cyphertext, dtype=np.int32)
    end = time.time()
    if(print_debug): print("Arrays created in ",end-start, " seconds")


    if not first_time:
        event.wait()
        cl.enqueue_copy(queue, b, b_dev)
        endk = time.time()
        if(print_debug): print("Kernel completed in ",endk-startk, " 
seconds")
        if b[0] == 1:
            s = 32*b[1]+4
            f = s+28
            print("*** Possible password candidate found: 
",buf2[s:f].decode('utf-8'))


    start = time.time()
    if first_time:
        iv_dev = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | 
cl.mem_flags.COPY_HOST_PTR, hostbuf=IV)
        ct_dev = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | 
cl.mem_flags.COPY_HOST_PTR, hostbuf=CT)
    a_dev = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | 
cl.mem_flags.COPY_HOST_PTR, hostbuf=buf)
    b_dev = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY, b.nbytes)
    end = time.time()
    if(print_debug): print("Done in ",end-start, " seconds")


    startk = time.time()
    event = prg.hash_main(queue, (NoPasswords,) ,None, a_dev, 
b_dev,iv_dev,ct_dev)
    first_time = False
    buf2 = buf

event.wait()
cl.enqueue_copy(queue, b, b_dev)
endk = time.time()
if(print_debug): print("Kernel completed in ",endk-startk, " seconds")
if b[0] == 1:
    s = 32*b[1]+4
    f = s+28
    print("*** Possible password candidate found: 
",buf2[s:f].decode('utf-8'))
    
    
tend = time.time()
print("All completed in ",tend-tstart, " seconds")
print("Guess rate per second: ",int(totalPass/(tend-tstart)))


