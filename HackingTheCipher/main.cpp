#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iostream>

using namespace std;

const int KEY_NUM = 12;


void setTargetPubKeys(int &t1, int &t2, RSA **rsaPubs) 
{

  BIGNUM *res = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  for(int i = 0 ; i < KEY_NUM ; i ++) {
    for(int j = i + 1 ; j < KEY_NUM ; j ++) {
      BN_gcd(res, rsaPubs[i]->n, rsaPubs[j]->n, ctx);
      if(BN_is_one(res) != 1) {
        t1 = i;
        t2 = j;

        BN_CTX_free(ctx);
        BN_free(res);

        return;
      }
    }
  }
}

void getPubFromFile(RSA **rsaPubs) 
{

  string fileName = "";
  FILE *keyfile = NULL; 
  
  for(int i = 0 ; i < KEY_NUM ; i ++) {
    fileName = "cert" + to_string(i+1) + ".pub";
    keyfile = fopen(fileName.c_str(), "r");
    rsaPubs[i] = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
  }

}

int main ()
{

  // Array of all RSA public keys .
  RSA **rsaPubs = NULL;
  rsaPubs = (RSA**)malloc(sizeof(RSA*) * (KEY_NUM + 1));
  
  // Get keys from file .
  getPubFromFile(rsaPubs);

  // Search two public keys with common factor .
  int targetPubKeyIndex_1, targetPubKeyIndex_2;
  setTargetPubKeys(targetPubKeyIndex_1, targetPubKeyIndex_2, rsaPubs);

  cout << "Target Public Key Number : " << targetPubKeyIndex_1 + 1 << ", " << targetPubKeyIndex_2 + 1 << endl;
  cout << endl;
  
  // Calculate common factor .
  BIGNUM *commonFactor = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_gcd(commonFactor, rsaPubs[targetPubKeyIndex_1]->n, rsaPubs[targetPubKeyIndex_2]->n, ctx);
  cout << "Common Factor :" << endl;
  BN_print_fp(stdout,commonFactor);
  cout << endl; 
  cout << endl; 

  // Calculate PubKey1 & PubKey2's q .
  BIGNUM *pub1_q = BN_new();
  BIGNUM *pub2_q = BN_new();

  BN_div(pub1_q, NULL, rsaPubs[targetPubKeyIndex_1]->n, commonFactor,ctx);
  cout << "Public Key " << targetPubKeyIndex_1 + 1 << "'s q :" << endl; 
  BN_print_fp(stdout,pub1_q);
  cout << endl; 
  BN_div(pub2_q, NULL, rsaPubs[targetPubKeyIndex_2]->n, commonFactor,ctx);
  cout << "Public Key " << targetPubKeyIndex_2 + 1 << "'s q :" << endl; 
  BN_print_fp(stdout,pub2_q);
  cout << endl;
  cout << endl;  
  
  // Calculate PubKey1 & PubKey2's Q(n) .
  BIGNUM *pub1_Qn = BN_new();
  BIGNUM *pub2_Qn = BN_new();
  
  BIGNUM *pSub = BN_new();
  BIGNUM *pub1_qSub = BN_new();
  BIGNUM *pub2_qSub = BN_new();

  BN_sub(pSub, commonFactor, BN_value_one());
  BN_sub(pub1_qSub, pub1_q, BN_value_one());
  BN_sub(pub2_qSub, pub2_q, BN_value_one());

  BN_mul(pub1_Qn, pSub, pub1_qSub, ctx);
  // BN_print_fp(stdout,pub1_Qn);
  BN_mul(pub2_Qn, pSub, pub2_qSub, ctx);
  // BN_print_fp(stdout,pub2_Qn);

  // Calculate PubKey1 & PubKey2's private key .
  BIGNUM *priKey1 = BN_new();
  BIGNUM *priKey2 = BN_new();

  BN_mod_inverse(priKey1, rsaPubs[targetPubKeyIndex_1]->n, pub1_Qn, ctx);
  cout << "Private Key " << targetPubKeyIndex_1 + 1 << " :" << endl;
  BN_print_fp(stdout, priKey1);
  cout << endl; 
  BN_mod_inverse(priKey2, rsaPubs[targetPubKeyIndex_2]->n, pub2_Qn, ctx);
  cout << "Private Key " << targetPubKeyIndex_2 + 1 << " :" << endl;
  BN_print_fp(stdout, priKey2);
  cout << endl;

  string private1FileName = "private" + to_string(targetPubKeyIndex_1 + 1) + ".pem";
  string private2FileName = "private" + to_string(targetPubKeyIndex_2 + 1) + ".pem";

  FILE *pri1_file = fopen(private1FileName.c_str(), "ab+");
  FILE *pri2_file = fopen(private2FileName.c_str(), "ab+");

  RSA *pri1_RSA = RSA_new();
  RSA *pri2_RSA = RSA_new();

  pri1_RSA->d = priKey1;
  pri2_RSA->d = priKey2;

  PEM_write_RSAPrivateKey(pri1_file, pri1_RSA, NULL, NULL, 0, 0, NULL);
  PEM_write_RSAPrivateKey(pri2_file, pri2_RSA, NULL, NULL, 0, 0, NULL);


  // Free resources .
  BN_free(commonFactor);
  BN_free(pub1_q);
  BN_free(pub2_q);
  BN_free(pub1_Qn);
  BN_free(pub2_Qn);
  BN_free(pSub);
  BN_free(pub1_qSub);
  BN_free(pub2_qSub);
  BN_free(priKey1);
  BN_free(priKey2);
  BN_CTX_free(ctx);

  fclose(pri1_file);
  fclose(pri2_file);

  return 0;
}