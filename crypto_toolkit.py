
#!/usr/bin/env python3
"""
CTF Crypto Toolkit (Educational / Authorized CTF Use Only)

Requirements:
    pip install pycryptodome sympy requests

Features
--------
1. Hex Encode/Decode
2. Base64 Encode/Decode
3. Base32 Encode/Decode
4. URL Encode/Decode
5. Binary <-> ASCII
6. Single-byte XOR Bruteforce
7. Repeating-key XOR
8. Caesar Bruteforce
9. RSA Helper (decrypt with p,q)
10. GCD / Modular Inverse
11. Hashes (MD5/SHA1/SHA256)
12. Entropy
13. File Signature Detector
14. Frequency Analysis
"""

import base64, hashlib, urllib.parse, math
from collections import Counter

try:
    from Crypto.Util.number import inverse, long_to_bytes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

MAGIC = {
    b"\x89PNG":"PNG",
    b"\xff\xd8\xff":"JPEG",
    b"%PDF":"PDF",
    b"PK\x03\x04":"ZIP",
    b"\x7fELF":"ELF",
    b"GIF89a":"GIF",
    b"GIF87a":"GIF",
}

def banner():
    print("="*60)
    print("CTF CRYPTO TOOLKIT")
    print("="*60)

def pause():
    input("\nPress Enter...")

def hex_decode():
    s=input("Hex: ").strip()
    try:
        b=bytes.fromhex(s)
        print("Bytes:",b)
        print("Text :",b.decode(errors="ignore"))
    except Exception as e:
        print(e)

def hex_encode():
    print(input("Text: ").encode().hex())

def b64_decode():
    s=input("Base64: ").strip()
    try:
        b=base64.b64decode(s)
        print(b)
        print(b.decode(errors="ignore"))
    except Exception as e:
        print(e)

def b64_encode():
    print(base64.b64encode(input("Text: ").encode()).decode())

def b32_decode():
    print(base64.b32decode(input("Base32: ")).decode(errors="ignore"))

def b32_encode():
    print(base64.b32encode(input("Text: ").encode()).decode())

def url_decode():
    print(urllib.parse.unquote(input("URL: ")))

def url_encode():
    print(urllib.parse.quote(input("Text: ")))

def binary_ascii():
    c=input("1.Binary->ASCII 2.ASCII->Binary : ")
    if c=="1":
        bits=input("Binary: ").replace(" ","")
        out="".join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8))
        print(out)
    else:
        print(" ".join(format(ord(x),"08b") for x in input("ASCII: ")))

def xor_single():
    data=bytes.fromhex(input("Cipher Hex: "))
    for k in range(256):
        p=bytes(x^k for x in data)
        try:
            txt=p.decode()
            if all(32<=ord(c)<=126 for c in txt):
                print(f"{k:02x}: {txt}")
        except:
            pass

def xor_repeat():
    data=bytes.fromhex(input("Cipher Hex: "))
    key=input("Key: ").encode()
    out=bytes(data[i]^key[i%len(key)] for i in range(len(data)))
    print(out)
    print(out.decode(errors="ignore"))

def caesar():
    t=input("Cipher: ")
    for s in range(26):
        out=""
        for c in t:
            if c.isalpha():
                b=65 if c.isupper() else 97
                out+=chr((ord(c)-b-s)%26+b)
            else:
                out+=c
        print(s,out)

def rsa():
    if not HAVE_CRYPTO:
        print("Install pycryptodome")
        return
    p=int(input("p="))
    q=int(input("q="))
    e=int(input("e="))
    c=int(input("cipher="))
    n=p*q
    phi=(p-1)*(q-1)
    d=inverse(e,phi)
    m=pow(c,d,n)
    print("n =",n)
    print("phi =",phi)
    print("d =",d)
    print("Message =",long_to_bytes(m))

def gcd_inverse():
    if not HAVE_CRYPTO:
        print("Install pycryptodome")
        return
    from math import gcd
    a=int(input("a="))
    b=int(input("b="))
    print("gcd =",gcd(a,b))
    try:
        print("inverse =",inverse(a,b))
    except:
        print("No modular inverse")

def hashes():
    t=input("Text: ").encode()
    print("MD5    ",hashlib.md5(t).hexdigest())
    print("SHA1   ",hashlib.sha1(t).hexdigest())
    print("SHA256 ",hashlib.sha256(t).hexdigest())

def entropy():
    f=input("File: ")
    data=open(f,"rb").read()
    cnt=Counter(data)
    e=0
    for v in cnt.values():
        p=v/len(data)
        e-=p*math.log2(p)
    print("Entropy =",e)

def magic():
    f=input("File: ")
    d=open(f,"rb").read(16)
    for sig,name in MAGIC.items():
        if d.startswith(sig):
            print(name)
            return
    print("Unknown")

def freq():
    f=input("File/Text: ")
    try:
        data=open(f,"rb").read()
    except:
        data=f.encode()
    for k,v in Counter(data).most_common(20):
        print(repr(bytes([k])),v)

MENU=[
("Hex Decode",hex_decode),
("Hex Encode",hex_encode),
("Base64 Decode",b64_decode),
("Base64 Encode",b64_encode),
("Base32 Decode",b32_decode),
("Base32 Encode",b32_encode),
("URL Decode",url_decode),
("URL Encode",url_encode),
("Binary/ASCII",binary_ascii),
("Single-byte XOR",xor_single),
("Repeating-key XOR",xor_repeat),
("Caesar Bruteforce",caesar),
("RSA Helper",rsa),
("GCD/Inverse",gcd_inverse),
("Hashes",hashes),
("Entropy",entropy),
("Magic Detector",magic),
("Frequency Analysis",freq)
]

def main():
    while True:
        banner()
        for i,(n,_) in enumerate(MENU,1):
            print(f"{i:2}. {n}")
        print(" 0. Exit")
        try:
            c=int(input("> "))
        except:
            continue
        if c==0:
            break
        if 1<=c<=len(MENU):
            print()
            MENU[c-1][1]()
            pause()

if __name__=="__main__":
    main()
