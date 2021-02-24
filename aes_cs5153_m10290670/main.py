from textwrap import wrap
import sys


def AddKey1(plaintextfilepath, subkeyfilepath): #Add Round Key, Round 0
    str = open(plaintextfilepath, "r").read() #read plaintext
    encrypted = str.encode().hex()  #turn plaintext into hexadecimal
    subkey1 = open(subkeyfilepath, "r").readlines()[0] #read subkey0
    str1 = wrap(encrypted, 2)   #turn into list of 2 at a time
    subk1 = wrap(subkey1, 2)
    addkey1 = []
    scale = 16
    num_of_bits = 8
    for i in range(len(str)):
        key = xor(bin(int(str1[i], scale))[2:].zfill(num_of_bits), bin(int(subk1[i], scale))[2:].zfill(num_of_bits)) #addition in binary
        addkey1.append(key)
    hexstr = []
    for a in addkey1:
        hexstr.append('{:0{}X}'.format(int(a, 2), len(a) // 4)) #add to list in hexadecimal
    return hexstr


def SubBytes(AddKey1):          #Substituition Bytes
    sbox = [
        ["63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"],
        ["ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"],
        ["b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"],
        ["04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"],
        ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
        ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
        ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
        ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
        ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
        ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
        ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
        ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
        ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
        ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
        ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
        ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']
    ]
    subbytes = []
    for a in AddKey1:               #Compare and Substitute Bytes based on hexadecimal, if hex contains a character then it is transalted into numbers to match with 2darray defined above
        if a[1] == "A":
            x = "10"
        elif a[1] == "B":
            x = "11"
        elif a[1] == "C":
            x = "12"
        elif a[1] == "D":
            x = "13"
        elif a[1] == "E":
            x = "14"
        elif a[1] == "F":
            x = "15"
        else:
            x = a[1]

        if a[0] == "A":
            y = "10"
        elif a[0] == "B":
            y = "11"
        elif a[0] == "C":
            y = "12"
        elif a[0] == "D":
            y = "13"
        elif a[0] == "E":
            y = "14"
        elif a[0] == "F":
            y = "15"
        else:
            y = a[0]
        subbytes.append((sbox[int(y)][int(x)]))
    return subbytes


def xor(x, y):              #simple addition operation
    return '{1:0{0}b}'.format(len(x), int(x, 2) ^ int(y, 2))


def ShiftRows(SubBytes):        #manual shifting rows
    shiftrows = []
    shiftrows.append(SubBytes[0])
    shiftrows.append(SubBytes[5])
    shiftrows.append(SubBytes[10])
    shiftrows.append(SubBytes[15])
    shiftrows.append(SubBytes[4])
    shiftrows.append(SubBytes[9])
    shiftrows.append(SubBytes[14])
    shiftrows.append(SubBytes[3])
    shiftrows.append(SubBytes[8])
    shiftrows.append(SubBytes[13])
    shiftrows.append(SubBytes[2])
    shiftrows.append(SubBytes[7])
    shiftrows.append(SubBytes[12])
    shiftrows.append(SubBytes[1])
    shiftrows.append(SubBytes[6])
    shiftrows.append(SubBytes[11])
    return shiftrows


def multiply(b,a):          #multiplication function
    if b == 1:
        return a
    tmp = (a<<1) & 0xff
    if b == 2:
        return tmp if a < 127 else tmp^0x1b
    if b == 3:
        return tmp^a if a < 127 else (tmp^0x1b)^a


def MixColumns(ShiftRows):  #Shift Rows Function
    shiftrowsdec = []
    for a in ShiftRows:
        shiftrowsdec.append(int(a, 16))
    mixcolumns = []
    #All of these are, product XOR (product XOR (product XOR product)), still fully adaptive to change in subkey and plaintext
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(2, shiftrowsdec[0]), "08b"), format(multiply(3, shiftrowsdec[1]), "08b")),
            format(multiply(1, shiftrowsdec[2]), "08b")), format(multiply(1, shiftrowsdec[3]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[0]), "08b"), format(multiply(2, shiftrowsdec[1]), "08b")),
            format(multiply(3, shiftrowsdec[2]), "08b")), format(multiply(1, shiftrowsdec[3]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[0]), "08b"), format(multiply(1, shiftrowsdec[1]), "08b")),
            format(multiply(2, shiftrowsdec[2]), "08b")), format(multiply(3, shiftrowsdec[3]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(3, shiftrowsdec[0]), "08b"), format(multiply(1, shiftrowsdec[1]), "08b")),
            format(multiply(1, shiftrowsdec[2]), "08b")), format(multiply(2, shiftrowsdec[3]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(2, shiftrowsdec[4]), "08b"), format(multiply(3, shiftrowsdec[5]), "08b")),
            format(multiply(1, shiftrowsdec[6]), "08b")), format(multiply(1, shiftrowsdec[7]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[4]), "08b"), format(multiply(2, shiftrowsdec[5]), "08b")),
            format(multiply(3, shiftrowsdec[6]), "08b")), format(multiply(1, shiftrowsdec[7]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[4]), "08b"), format(multiply(1, shiftrowsdec[5]), "08b")),
            format(multiply(2, shiftrowsdec[6]), "08b")), format(multiply(3, shiftrowsdec[7]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(3, shiftrowsdec[4]), "08b"), format(multiply(1, shiftrowsdec[5]), "08b")),
            format(multiply(1, shiftrowsdec[6]), "08b")), format(multiply(2, shiftrowsdec[7]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(2, shiftrowsdec[8]), "08b"), format(multiply(3, shiftrowsdec[9]), "08b")),
            format(multiply(1, shiftrowsdec[10]), "08b")), format(multiply(1, shiftrowsdec[11]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[8]), "08b"), format(multiply(2, shiftrowsdec[9]), "08b")),
            format(multiply(3, shiftrowsdec[10]), "08b")), format(multiply(1, shiftrowsdec[11]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[8]), "08b"), format(multiply(1, shiftrowsdec[9]), "08b")),
            format(multiply(2, shiftrowsdec[10]), "08b")), format(multiply(3, shiftrowsdec[11]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(3, shiftrowsdec[8]), "08b"), format(multiply(1, shiftrowsdec[9]), "08b")),
            format(multiply(1, shiftrowsdec[10]), "08b")), format(multiply(2, shiftrowsdec[11]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(2, shiftrowsdec[12]), "08b"), format(multiply(3, shiftrowsdec[13]), "08b")),
            format(multiply(1, shiftrowsdec[14]), "08b")), format(multiply(1, shiftrowsdec[15]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[12]), "08b"), format(multiply(2, shiftrowsdec[13]), "08b")),
            format(multiply(3, shiftrowsdec[14]), "08b")), format(multiply(1, shiftrowsdec[15]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(1, shiftrowsdec[12]), "08b"), format(multiply(1, shiftrowsdec[13]), "08b")),
            format(multiply(2, shiftrowsdec[14]), "08b")), format(multiply(3, shiftrowsdec[15]), "08b")), 2)))
    mixcolumns.append(hex(int(xor(
        xor(xor(format(multiply(3, shiftrowsdec[12]), "08b"), format(multiply(1, shiftrowsdec[13]), "08b")),
            format(multiply(1, shiftrowsdec[14]), "08b")), format(multiply(2, shiftrowsdec[15]), "08b")), 2)))
    return mixcolumns


def AddKey2(MixColumns, subkeyfilepath): #Add Round Key, Round 1
    subkey2 = open(subkeyfilepath, "r").readlines()[1] # read subkey1
    subk2 = wrap(subkey2, 2) #turn subkey into list of size 2
    scale = 16
    num_of_bits = 8
    addkey2 = []
    for i in range(len(MixColumns)):
        key = xor(bin(int(MixColumns[i], scale))[2:].zfill(num_of_bits),
                  bin(int(subk2[i], scale))[2:].zfill(num_of_bits))#addition in binary
        addkey2.append(key)
    hexstr = []
    for a in addkey2:
        hexstr.append('{:0{}X}'.format(int(a, 2), len(a) // 4)) #add to list in hexadecimal
    return hexstr


def WriteResultToFile(hexstr, resultfilepath):
    resultstr=""
    for i in hexstr:
        resultstr+=i        #turn list into string
    print("Result after first round of AES is " + resultstr) #print out string
    open(resultfilepath, "w").write(resultstr) #write string result to file


if __name__ == '__main__':
    AddKey1 = AddKey1(sys.argv[1], sys.argv[2])
    SubBytes = SubBytes(AddKey1)
    ShiftRows = ShiftRows(SubBytes)
    MixColumns = MixColumns(ShiftRows)
    result = AddKey2(MixColumns, sys.argv[2])
    WriteResultToFile(result, sys.argv[3])