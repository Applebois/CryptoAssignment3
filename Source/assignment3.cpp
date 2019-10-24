//Generate an RSA key pair, sign a message and verify it using crypto++ 5.6.1 or later.
//By Tim Sheerman-Chase, 2013
//This code is in the public domain and CC0
//To compile: g++ gen.cpp -lcrypto++ -o gen

////////////INCLUDE COLOUR CODE///////////////////
#ifndef _COLORS_
#define _COLORS_
#define RST  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define FRED(x) KRED x RST
#define FGRN(x) KGRN x RST
#define FYEL(x) KYEL x RST
#define FBLU(x) KBLU x RST
#define FMAG(x) KMAG x RST
#define FCYN(x) KCYN x RST
#define FWHT(x) KWHT x RST
#define BOLD(x) "\x1B[1m" x RST
#define UNDL(x) "\x1B[4m" x RST
#endif  /* _COLORS_ */
/////////////END OF INCLUDE COLOR CODE////////////////////


#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/md5.h"
#include "cryptopp/cryptlib.h"

#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h> 
#include <string>
#include <iostream>

#include <cryptopp/files.h>
#include <string>
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/rsa.h"
#include <iostream>
#include "cryptopp/hex.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include <fstream>
using namespace CryptoPP;
using namespace std;
string sha1file();
string filehash;
void GenKeyPair()
{
	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	Base64Encoder privkeysink(new FileSink("privkey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	RSAFunction pubkey(privkey);
	
	Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();
	cout<<"\n\n";
	cout<<"Private Key :"<<endl;
	system("cat privkey.txt");
	cout<<"\n\n";
	cout<<"Public Key :"<<endl;	
	system("cat pubkey.txt");

}

void Sign()
{
	string hashvalue=sha1file();
	filehash=hashvalue;
	string strContents = hashvalue ;
	AutoSeededRandomPool rng;
	//Read private key
	CryptoPP::ByteQueue bytes;
	FileSource file("privkey.txt", true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PrivateKey privateKey;
	privateKey.Load(bytes);
	string signature;
	//Sign message
	RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
	StringSource ss1(filehash, true,new SignerFilter(rng, privkey, new HexEncoder ( new StringSink(signature)) ) // SignerFilter 
	); // StringSource
	//Save result
	FileSink sink("signed.dat");
	sink.Put((byte const*) strContents.data(), strContents.size());
	cout<<endl;
	cout<<signature<<endl;
	ofstream write;
        write.open ("sig.dat");
        write << signature;
	write.close();
}

int Verify()
{
	//Read public key
	CryptoPP::ByteQueue bytes;
	FileSource file("pubkey.txt", true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PublicKey pubKey;
	pubKey.Load(bytes);
	RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);
	string filename;
	//Read signed message
	string signedTxt;
	FileSource("signed.dat", true, new StringSink(signedTxt));
	string sig;
	FileSource("sig.dat", true, new HexDecoder ( new StringSink(sig)));
	string combined(signedTxt);
	combined.append(sig);
	cout<<"\n\n";
	CryptoPP::SHA1 sha1;
	std::string source = signedTxt;  //This will be randomly generated somehow
	std::string hash = "";
	//Verify signature
	try
	{
		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
		cout<<"Plaintext hash : "<<filehash<<endl;
		cout<<"Cipher decrypted using signature : "<<signedTxt<<endl;
		cout << "Signature OK" << endl;
	}
	catch(SignatureVerificationFilter::SignatureVerificationFailed &err)
	{
		cout << err.what() << endl;
	return 1;
	}
}


void md5file()
{
using namespace CryptoPP;
HexEncoder encoder(new FileSink(std::cout));
cout<<"               _ _____ "<<endl;
cout<<"              | |  ___|"<<endl;
cout<<" _ __ ___   __| |___ \\ "<<endl;
cout<<"| '_ ` _ \\ / _` |   \\ \\"<<endl;
cout<<"| | | | | | (_| /\\__/ /"<<endl;
cout<<"|_| |_| |_|\\__,_\\____/ "<<endl;

cout<<"Enter file name:  ";
//std::string msg = "Enter file name ";
string a;
cin>>a;
ifstream myfile (a);
if(myfile.fail())
        {
      cout<<"Input file not found, program quit "<<endl;
        exit(0);
        }

    string result;
    CryptoPP::Weak::MD5 hash;
    char* file = new char[a.length() + 1];
    strcpy(file, a.c_str());

    CryptoPP::FileSource( ( file ),true,
        new CryptoPP::HashFilter(
            hash, new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(result), false)
        )
    );
	cout<<BOLD(FRED("Checksum : "));
    cout<<result<< endl;

}



string sha1file()
{
using namespace CryptoPP;
HexEncoder encoder(new FileSink(std::cout));
cout<<"     _           __  "<<endl;
cout<<"    | |         /  | "<<endl;
cout<<" ___| |__   __ _`| | "<<endl;
cout<<"/ __| '_ \\ / _` || | "<<endl;
cout<<"\\__ \\ | | | (_| || |_"<<endl;
cout<<"|___/_| |_|\\__,_\\___/"<<endl;


cout<<"Enter file name:  ";
//std::string msg = "Enter file name ";
string a;
cin>>a;
ifstream myfile (a);
if(myfile.fail())
        {
      cout<<"Input file not found, program quit "<<endl;
        exit(0);
        }

    string result;
    CryptoPP::SHA1 hash;
    char* file = new char[a.length() + 1];
    strcpy(file, a.c_str());

    CryptoPP::FileSource( ( file ),true,
        new CryptoPP::HashFilter(
            hash, new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(result), false)
        )
    );
    cout<<BOLD(FRED("Checksum : "));
	cout<<result;
	return result;
}

int main(int argc, char* argv[])
{
int decision=0;	
do{
	a:
	cout<<BOLD(FWHT("\n\n           _                            "))<<endl;
	cout<<BOLD(FRED("          (_)                          "))<<endl;
	cout<<BOLD(FBLU(" __      ___ _ __  ___  __ _ _ __ ___  "))<<endl;
	cout<<BOLD(FGRN(" \\ \\ /\\ / / | '_ \\/ __|/ _` | '_ ` _ \\ "))<<endl;
	cout<<BOLD(FMAG("  \\ V  V /| | | | \\__ \\ (_| | | | | | |  "))<<endl;
	cout<<BOLD(FRED("   \\_/\\_/ |_|_| |_|___/\\__,_|_| |_| |_|  "))<<endl;
	cout<<BOLD("            _ __ ___  __ _ ")<<endl;
	cout<<BOLD("           | '__/ __|/ _` |")<<endl;
	cout<<BOLD("           | |  \\__ \\ (_| |")<<endl;
	cout<<BOLD("           |_|  |___/\\__,_|")<<endl;
	cout<<"\n\n\t\t MENU\n\n"<<endl;
	cout<<"1.	Generate RSA Signature for a file"<<endl;
	cout<<"2.	Verify a Signature of a file"<<endl;
	cout<<"3.	Create MD-5 Hash for a file"<<endl;
	cout<<"4.	Create SHA-1 Hash for a file"<<endl;
	cout<<"5.	Quit"<<endl;
	cout<<"root@winsam:~";
	cin>>decision;
	if(decision < 1 || decision > 5 )
	{
//		system("cls");
		system("clear");
//		cout<<"Invalid Choice"<<endl;
cout<<BOLD(FRED("\n\n-------------------------------------------------------------------------------------------------\n|\t\t\t\t\t\t\t\t\t\t\t\t|\n"));
cout<<BOLD(FRED("|\t\t(_)               | (_)   | |     | |         (_)   (_)            \t\t|"))<<endl;
cout<<BOLD(FRED("|\t\t _ _ ____   ____ _| |_  __| |   __| | ___  ___ _ ___ _  ___  _ __  \t\t|"))<<endl;
cout<<BOLD(FRED("|\t\t| | '_ \\ \\ / / _` | | |/ _` |  / _` |/ _ \\/ __| / __| |/ _ \\| '_ \\ \t\t|"))<<endl;
cout<<BOLD(FRED("|\t\t| | | | \\ V / (_| | | | (_| | | (_| |  __/ (__| \\__ \\ | (_) | | | |\t\t|"))<<endl;
cout<<BOLD(FRED("|\t\t|_|_| |_|\\_/ \\__,_|_|_|\\__,_|  \\__,_|\\___|\\___|_|___/_|\\___/|_| |_|\t\t|"))<<endl;
cout<<BOLD(FRED("|\t\t\t\t\t\t\t\t\t\t\t\t|\n|\t\t\t\t\t\t\t\t\t\t\t\t|\n-------------------------------------------------------------------------------------------------"))<<endl;
		goto a;
	}
	if(decision==1)
	{
	GenKeyPair();
	Sign();
	}
	else if(decision==2)
	{
	Verify();
	}
	else if(decision==3)
	{
	md5file();
	}
	else if(decision==4)
	{
	sha1file();
	}
	else
	{
	exit (0);
	}
	cout<<endl;
	}while(decision!=5);
}

