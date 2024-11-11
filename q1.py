from sympy.ntheory import factorint;  #pip install sympy
import gmpy2 #pip install gmpy2
import math
'''

Prémisse:


“Alain Tapp”
= [A,l,a,i,n,_,T,a,p,p]
= [65, 108, 97, 105, 110, 32, 84, 97, 112, 112]
= [01000001, 01101100, 01100001, 01101001, 01101110,
   00100000, 01010100, 01100001, 01110000, 01110000]
= 01000001011011000110000101101001011011100010000001010100011000010111000001110000
= 308953089009066937774192





'''

import math
import random as rnd
import numpy as np
#import requests
from collections import Counter

# convert string to list of integer
def str_to_int_list(x):
  z = [ord(a) for a in x  ]
  for x in z:
    if x > 256:
      print(x)
      return False
  return z

# convert a strint to an integer
def str_to_int(x):
  x = str_to_int_list(x)
  if x == False:
    print("Le text n'est pas compatible!")
    return False

  res = 0
  for a in x:
    res = res * 256 + a
  i = 0
  res = ""
  for a in x:
    ci = "{:08b}".format(a )
    if len(ci)>8:
      print()
      print("long",a)
      print()
    res = res + ci
  res = eval("0b"+res)
  return res


cs = {"A","é","!"}
for c in cs:
  print(c,"=",ord(c),"=","{:08b}".format(ord(c) ))


M="Alain Tapp"
print(M)
print(list(M))
print(list(map(ord,list(M))))
print(str_to_int("Alain Tapp"))

# exponentiation modulaire
def modular_pow(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if (exponent % 2 == 1):
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# inverse multiplicatif de a modulo m
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("Pas d'inverse multiplicatif")
    else:
      return x % m
    


#Rappel : RSA(M) = C
#equiv a : 

"""
Pseudocode RSA : 

//Function to compute the greatest common divisor (GCD)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

// Function to compute modular inverse using the Extended Euclidean Algorithm
def modular_inverse(e, phi):
    old_r, r = phi, e
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    // Ensure result is positive
    return old_s % phi

// Key generation function for RSA-1
def generate_rsa_keys(p, q):
    //Step 1: Calculate n
    n = p * q
    //Step 2: Compute Euler's totient function (phi)
    phi = (p - 1) * (q - 1)
    //Step 3: Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
    e = 3
    while gcd(e, phi) != 1:
        e += 2  # Ensure e is odd for better security
    //Step 4: Calculate the modular inverse of e mod phi to get the private key d
    d = modular_inverse(e, phi)
    //Public and Private Key pair
    public_key = (e, n)
    private_key = (d, n)
    //
    return public_key, private_key


// RSA encryption function (public key encryption)
def rsa_encrypt(message, public_key):
    e, n = public_key
    //Convert the message to a number (for simplicity, assume message is already a number)
    ciphertext = pow(message, e, n) //modular exponentiation
    return ciphertext


//RSA decryption function (private key decryption)
def rsa_decrypt(ciphertext, private_key):  //modular inverse
    d, n = private_key
    //Decrypt the ciphertext using the private key
    message = pow(ciphertext, d, n) //modular exponentiation
    return message


//Example usage:
//Prime numbers (small primes used here for simplicity; in practice, they must be large)
p = 61
q = 53
//Generate keys
public_key, private_key = generate_rsa_keys(p, q)
//Encrypt a message (for simplicity, assume the message is a number)
message = 42
ciphertext = rsa_encrypt(message, public_key)
//Decrypt the ciphertext
decrypted_message = rsa_decrypt(ciphertext, private_key)


"""

# RSA textbook = Unpadded
#vulnérable a :
#Known plaintext attacks -> We can recognize repetitions  -> Key exposure
#Chosen plaintext attacks -> Designer un ciphertext et observer les patterns dans le plaintext -> Key exposure
#Low exponent attack -> e=3 -> parfait pour ce contexte


#logique d'un low exponent attack : https://www.youtube.com/watch?v=73oKv-8bPp0
#https://www.youtube.com/watch?v=2QGDsDfNjWc tuto python

# e.d = 1mod phi(n) = 1 + k phi(n)      tq  k/d approx e/N
#si d < 1/3 N^1/4   alors vulnérable



#Rappel
# N = PQ
# 


#Idee Attaque 1 : Si N est petit, On peut factoriser N pour retrouver p et q
#et phi tq phi = (p-1)(q-1)
#et d = inverse(e,phi)
#et m = pow(c,d,n)
#On utiliserait la même méthode que dans le tuto  #https://www.youtube.com/watch?v=WvqoKl_LI4I&list=PLX3dA7a5RDPYzS7WUiuLktRJXPqaFHk58&index=3

#ici N est grand, alors probablement impossible a factoriser dans le temps alloué pour la remise de ce tp


#Idée Attaque 2 : Est-ce que la paire p,q existe dans https://factordb.com/ ou https://www.alpertron.com.ar/ECM.HTM ?
#On utilise la même méthode que l'attaque 1, mais on utilise une database qui contient déjà les facteurs
#On trouve un résultat sur alpertron, les valeurs de p et q étaient dans la database, voir code plus bas


def attaque1(n,e,c):
   dictionnary = factorint(n)  #sort of bruteforce
   attaque2(dictionnary[0],dictionnary[1],n,e,c)

def attaque2(p,q,n,e,c):
   phi = (p-1)*(q-1)
   d = modinv(e,phi)
   m = modular_pow(c,d,n)
   printM(m)
      
def printM(m):
   binary = bin(m)[2:] 
   padded_binary = binary.zfill((len(binary) + 7) // 8 * 8) #le padding est essentiel à la lecture du message
   bytes = [padded_binary[i:i+8] for i in range(0, len(padded_binary), 8)] 
    #
   message=""
   for byte in bytes:
      value = int(str(byte),2)
      letter = chr(value)
      message+=letter
   print(message)
#printM(308953089009066937774192) #alain tapp test


# Clé publique Question 1.1
N = 143516336909281815529104150147210248002789712761086900059705342103220782674046289232082435789563283739805745579873432846680889870107881916428241419520831648173912486431640350000860973935300056089286158737579357805977019329557985454934146282550582942463631245697702998511180787007029139561933433550242693047924440388550983498690080764882934101834908025314861468726253425554334760146923530403924523372477686668752567287060201407464630943218236132423772636675182977585707596016011556917504759131444160240252733282969534092869685338931241204785750519748505439039801119762049796085719106591562217115679236583
e = 3
# Cryptogramme 1.1
C = 1101510739796100601351050380607502904616643795400781908795311659278941419415375
#essayons
p=10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046474983581941267398767559165543946077062914571196477686542167660429831652624386837205668073457
q=13393857589828341511855313113250022632017560146319170093046879854629388139061701531164979735196198226594933411469414335314839316071153925544980721968373218504918209718530288731776343256327963927347442727691308093729477426584248459448956929932596328643213995597108177709575537289565780483547741631653719
attaque2(p,q,N,e,C)
#
#Réponse Q1.1 : Umberto Eco

# Clé publique Question 1.2
N = 172219604291138178634924980176652297603347655313304280071646410523864939208855547078498922947475940487766894695848119416017067844129458299713889703424997977808694983717968420001033168722360067307143390485095229367172423195469582545920975539060699530956357494837243598213416944408434967474317474605697904676813343577310719430442085422937057220239881971046349315235043163226355302567726074269720408051461805113819456513196492192727498270702594217800502904761235711809203123842506621973488494670663483187137290546241477681096402483981619592515049062514180404818608764516997842633077157249806627735448350463
e = 173
# Cryptogramme 1.2
C = 25782248377669919648522417068734999301629843637773352461224686415010617355125387994732992745416621651531340476546870510355165303752005023118034265203513423674356501046415839977013701924329378846764632894673783199644549307465659236628983151796254371046814548224159604302737470578495440769408253954186605567492864292071545926487199114612586510433943420051864924177673243381681206265372333749354089535394870714730204499162577825526329944896454450322256563485123081116679246715959621569603725379746870623049834475932535184196208270713675357873579469122917915887954980541308199688932248258654715380981800909
#avec la même attaque via alpertron 
p=10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046474983581941267398767559165543946077062914571196477686542167660429831652624386837205668069673
q=16072629107794009814226375735900027158421072175583004111656255825555265766874041837397975682235437871913920093763297202377807179285384710653976866362047862205901851662236346478131611907593556712816931273229569712475372911901098151338748315919115594371856794716529813251490644747478936580257043048672231 
attaque2(p,q,N,e,C)
#
#réponse : Marcel Proust





#Pour rester de bonne foi et ne pas être pénalisé pour avoir trivialisé le problème, je vais implémenter une 3e attaque pour la Q1:

#Attaque sur valeurs de e petites (Source : https://www.youtube.com/watch?v=2QGDsDfNjWc&list=PLX3dA7a5RDPYzS7WUiuLktRJXPqaFHk58&index=6)
#C = M^e % N  ---> e root      ->si  C=M^e  < N   alors on peut simplement extraire le message en effectuant le nth root
def attaque3(N,e,C): #small msg attack
   msg, reste = gmpy2.iroot(C,e) #deconstruction
   printM(msg)



# Clé publique Question 1.1
N = 143516336909281815529104150147210248002789712761086900059705342103220782674046289232082435789563283739805745579873432846680889870107881916428241419520831648173912486431640350000860973935300056089286158737579357805977019329557985454934146282550582942463631245697702998511180787007029139561933433550242693047924440388550983498690080764882934101834908025314861468726253425554334760146923530403924523372477686668752567287060201407464630943218236132423772636675182977585707596016011556917504759131444160240252733282969534092869685338931241204785750519748505439039801119762049796085719106591562217115679236583
e = 3
# Cryptogramme 1.1
C = 1101510739796100601351050380607502904616643795400781908795311659278941419415375
#

attaque3(N,e,C)





#Pour la q1.2, il faudra utiliser une stratégie différente car C est grand

# Clé publique Question 1.2
N = 172219604291138178634924980176652297603347655313304280071646410523864939208855547078498922947475940487766894695848119416017067844129458299713889703424997977808694983717968420001033168722360067307143390485095229367172423195469582545920975539060699530956357494837243598213416944408434967474317474605697904676813343577310719430442085422937057220239881971046349315235043163226355302567726074269720408051461805113819456513196492192727498270702594217800502904761235711809203123842506621973488494670663483187137290546241477681096402483981619592515049062514180404818608764516997842633077157249806627735448350463
e = 173
# Cryptogramme 1.2
C = 25782248377669919648522417068734999301629843637773352461224686415010617355125387994732992745416621651531340476546870510355165303752005023118034265203513423674356501046415839977013701924329378846764632894673783199644549307465659236628983151796254371046814548224159604302737470578495440769408253954186605567492864292071545926487199114612586510433943420051864924177673243381681206265372333749354089535394870714730204499162577825526329944896454450322256563485123081116679246715959621569603725379746870623049834475932535184196208270713675357873579469122917915887954980541308199688932248258654715380981800909
#
#Essayons de factoriser
#factorint(N) ne fonctionne pas ici
#assumons que p et q sont proches           https://www.youtube.com/watch?v=-ShwJqAalOk
#utilisons la factorisation Fermat pour vérifier si p et q sont très similaires et proches de la racine

def fermat_factorization(N):
    if N % 2 == 0:
        return [N // 2, 2]  # Fermat's factorization works for odd numbers only
    #
    a = math.isqrt(N) + 1  # Start with the smallest integer > sqrt(N)
    b2 = a * a - N         # Calculate b^2 = a^2 - N
    #
    it=0
    while not math.isqrt(b2) ** 2 == b2:  # Check if b2 is a perfect square
        a += 1
        b2 = a * a - N
        it+=1
        if it>200:
           print("unlikely to factor")
           break
    #
    b = math.isqrt(b2)  # Now b is the integer square root of b2
    return [a - b, a + b]  # Return factors (a - b) and (a + b)

def attaque4(N,e,C):
   if(N%2==0):
      print("on ne peut pas utiliser cette attaque")
   tableau = fermat_factorization(N)
   p=tableau[0]
   q=tableau[1]
   attaque2(p,q,N,e,C)


#attaque3(N,e,C)   on sait déjà que (Marcel Proust)^173 sera très grand et ne pourra pas fonctionner
# attaque4(N,e,C)   loop indéfiniment, alors pas intéressant pour notre contexte
