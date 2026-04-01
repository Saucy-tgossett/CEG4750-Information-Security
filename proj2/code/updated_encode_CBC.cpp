// CEG 4750 modified code

#include<iostream>
#include<fstream>
#include<sstream>
#include<string>
using namespace std;

#include"cryptopp/cryptlib.h"
#include"cryptopp/hex.h"
#include"cryptopp/filters.h"
#include"cryptopp/des.h"
#include"cryptopp/aes.h"
#include"cryptopp/modes.h"

using namespace CryptoPP;

string aes_encode(string & plain,byte key[], byte iv [])
{
	string cipher;
	try{
		CBC_Mode<AES>::Encryption enc;
		enc.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
		StringSource(plain, true, new StreamTransformationFilter(enc, new StringSink(cipher)));//add padding by StreamTransformationFilter 
	}
	catch(const CryptoPP::Exception & e)
	{
		cerr << "Encrytion error: " << e.what() << endl;
	}
	return cipher;
}

int main(int argc, char * argv[])
{
	fstream file1;
	fstream file2;
	byte key[AES::DEFAULT_KEYLENGTH];
	byte iv[AES::BLOCKSIZE];

	if(argc != 5)
	{
		cout << " usage:aes_encode infile outfile key iv" << endl;
		return 0;
	}
	
	file1.open(argv[1],ios::in);
	file2.open(argv[2],ios::out);
	
	//reading
	stringstream buffer;  
	buffer << file1.rdbuf();  
	string plain(buffer.str());  
	
	
	//get key
	memset(key, 0, AES::DEFAULT_KEYLENGTH);
	for(int i = 0;i < AES::DEFAULT_KEYLENGTH; i++)
	{
		if(argv[3][i]!='\0')
		{
			key[i]=(byte)argv[3][i];
		}				
		else
		{
			break;
		}
	}
	
	//get IV
	memset(iv, 0, AES::BLOCKSIZE);
	for (int i = 0; i < AES::BLOCKSIZE; i++){
		if (argv[4][i] != '\0') {
			iv[i] = (byte)argv[4][i];
		} else {
			break;
		}
	}
	
	
	//print key
	string encodedKey;
	encodedKey.clear();
	StringSource(key, sizeof(key), true, new HexEncoder( new StringSink(encodedKey))); 
	cout << "key: " << encodedKey << endl;

	//print IV
	string encodedIV;
	encodedIV.clear();
	StringSource(iv, sizeof(iv), true, new HexEncoder( new StringSink(encodedIV))); 
	cout << "iv: " << encodedIV << endl;
	
	//encode
	cout << "plain text: " << plain << endl;
	string cipher = aes_encode(plain,key, iv);
	file2 << cipher;
	cout << "cipher text stored in:" << argv[2] << endl;
	
	file1.close();
	file2.close();
	
	return 0;
}
