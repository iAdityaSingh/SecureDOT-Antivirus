import hashlib
import os

#global Variable
malware_hashes = list(open("virusHash.txt","r").read().split('\n'))
virusInfo = list(open("virusInfo.txt","r").read().split('\n'))

#get hash of File
def sha256_hash(filename):
    with open(filename, 'rb') as f:
        bytes = f.read()
        sha256_hash = hashlib.sha256(bytes).hexdigest()
        f.close()
        

    return sha256_hash

#malware Detection by hash
def malware_checker(pathOfFile):
    global malware_hashes
    global virusInfo

    hash_malware_check = sha256_hash(pathOfFile)
    counter = 0


    for i in malware_hashes:
        if i == hash_malware_check:
            return virusInfo[counter]
        counter += 1
    
    return 0
    
#malware detection in folder
virusName = []
virusPath = []

def virusScanner(path):

    #get the list of all files in directory tree at given path
    dir_list = list()
    for (dirpath, dirnames, filenames) in os.walk(path):
        dir_list += [os.path.join(dirpath, file) for file in filenames]

    for i in dir_list:
        print(i)
        if malware_checker(i) != 0:
            virusName.append(malware_checker(i)+" :: File :: "+i)
            virusPath.append(i)


# Virus Remover   

def virusRemover(path):
    virusScanner(path)
    if virusPath:
        for i in virusPath:
            os.remove(i)
        else:
            return 0
        

virusRemover("C:\\Users\\adity\\OneDrive\\Desktop\\testAv")
