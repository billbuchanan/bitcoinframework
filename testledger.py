#
# testLedger.py
# Written by Arran Holmes 40454196
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
os.environ["PYOPENCL_CTX"] = "0"
os.environ["PYOPENCL_COMPILER_OUTPUT"] = "1"

print("Ledger seed phrase brute forcing tool v0.1.9\nWritten by Arran 
Holmes.\nUsing the Hashcat crypto primative library for speed.\n")

# const definitions
ctx = cl.create_some_context()
queue = cl.CommandQueue(ctx)
wordSize = 4 #bytes
passwordBlockSize = 1000

#Load the seed word
seedword = b"\x50\x00\x00\x00topple provide provide burger ask trust 
couple bitter address object wine water"

# Load the OpenCL source files in order
print("Loading OpenCL source files")
code=""
files_to_compile = ["inc_vendor.h","inc_types.h","inc_platform.h", 
"inc_common.h", "inc_hash_sha512.h", "inc_ecc_secp256k1.h", 
"inc_platform.cl", "inc_common.cl", "inc_ecc_secp256k1.cl", 
"inc_hash_sha512.cl", "ledger_seed.cl"]
for file in files_to_compile:
    f =open(file,'r')
    code += f.read()
    code += "\n"

# Compile the OpenCL code
print("Compiling OpenCL kernel, this may take several minutes first time")
prg = cl.Program(ctx, code).build()

# Load the password list
f = open("dictionary.dict", mode="rb")
key = b''

while(True):
    buf = f.read(36* passwordBlockSize)
    if not buf:  break
    passNo = int(len(buf)/36)
    print("Loaded: ", passNo, " passwords")

    # Create the OpenCL buffers to transfer data to/from the GPU
    #print("Creating OpenCL buffers")
    c = np.zeros( 2, dtype=np.int32)
    a_dev = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | 
cl.mem_flags.COPY_HOST_PTR, hostbuf=buf)
    b_dev = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | 
cl.mem_flags.COPY_HOST_PTR, hostbuf=seedword)
    c_dev = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY, c.nbytes)

    # Start the OpenCL kernel
    #print("Starting the OpenCL kernel");
    start = time.time()
    event = prg.just_seed(queue, (1,) ,None, a_dev, b_dev, c_dev)
    event.wait()
    end = time.time()
    #print("Processed in ", end-start, " seconds")
    cl.enqueue_copy(queue, c, c_dev)
    if c[0] == 1:
        st = 36*c[1]+4
        ft = st+32
        print("**********************************")
        print("Possible password candidate found: 
",buf[st:ft].decode('utf-8'))
        print("**********************************")
    break
print ("Python Done")

