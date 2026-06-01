#include <iostream>
#include <chrono>
#include "aes.hpp"
#include "picosha2.h"
#include <iomanip>
#include <sstream>


extern "C"{
    #include "aes.c"
};
using namespace std;

#if defined(_WIN32)
    #include <windows.h>
    #include <wincrypt.h>
#else
    #include<fstream>
#endif

uint8_t pepper[] = {'I','H','a','t','e','F','u','r','r','i','e','s'};
string base_name = "vault";
string extension = ".txt";
int index = 1;
string current_filename = base_name + to_string(index) + extension;

bool fileExists(const string& filename){
    ifstream file(filename);
    return file.is_open();
}

void generateSecureBytes(uint8_t* key_array, int size) {
    
    #if defined(_WIN32)
        
        HCRYPTPROV hProvider = 0;
        if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(hProvider, size, key_array)) {
            std::cout << "successfully generated via Windows CryptoAPI.\n";
        } else {
            std::cout << "Failed to generate random bytes.\n";
        }
        CryptReleaseContext(hProvider, 0);
    } else {
        std::cout << "Failed to acquire cryptographic context.\n";
    }
        
    #else
        ifstream urandom("/dev/urandom", ios::binary);
        if (urandom) {
            urandom.read(reinterpret_cast<char*>(key_array), 32);
            urandom.close();
            cout << "Generated via Unix /dev/urandom.\n";
        }
    #endif
}

void paddingStrings(vector <uint8_t>& Password){
    int len = Password.size();
    int padding = 16 - (len % 16);
    
    for (int i = 0; i < padding; i++){
        Password.push_back(padding);
    }
}
void removePadding(vector <uint8_t>& vec){
    int size = vec.size();
    int pad = vec[size-1], count = 0;
    for (int i = size-1; i >= 0; i--){
        if (vec[i] == pad){
            count++;
        }
    }
    vec.resize(size-count);
    vec.shrink_to_fit();
}

string arrayToStrings(uint8_t* arr, int length){
    string str(arr, arr + length);
    return str;
}

vector<uint8_t> stringToArray(string str){
    vector <uint8_t> vec;
    for (int i = 0; i < str.length(); i++){
        vec.push_back(str[i]);
    }
    return vec;
}

vector<uint8_t> uintArrayToVector(uint8_t* arr, int size){
    vector<uint8_t> vec (arr, arr + size);
    return vec;
}

string hexToRaw(string str){
    string raw;
    for (int i = 0; i < str.length(); i += 2) {
            string hex_pair = str.substr(i, 2);
            char raw_byte = (char)stoi(hex_pair, nullptr, 16);
            raw += raw_byte;
        }
    return raw;
}

void stringCleaver(string current_line, string &site, string &iv_hex, string &pass_hex){
    stringstream ss(current_line);
    getline(ss, site, '|');     
    getline(ss, iv_hex, '|');   
    getline(ss, pass_hex);

}

void creatingVault(string site, vector <uint8_t> & pass_word, string User_PIN) {
    uint8_t my_DEK[32];
    uint8_t IV[16];
    uint8_t salt[16];
    
    uint8_t IV_kek[16];
    
    struct AES_ctx da_engine; 

    generateSecureBytes(my_DEK, 32);
    generateSecureBytes(IV, 16);
    generateSecureBytes(salt, 16);
    generateSecureBytes(IV_kek, 16);
    vector<uint8_t> my_DEKvec = uintArrayToVector(my_DEK, sizeof(my_DEK));
    
    string base_String = arrayToStrings(pepper, sizeof(pepper)) + User_PIN + arrayToStrings(salt, 16);
    string current = base_String, next, ver;
    
    for (int i = 0; i < 100000; i++){
        picosha2::hash256_hex_string(current,next);
        current = next;
    }
    vector <uint8_t> my_KEKvec = stringToArray(next);
    picosha2::hash256_hex_string(next,ver);
    vector <uint8_t> KEK_verify = stringToArray(ver);

    AES_init_ctx_iv(& da_engine, my_DEK, IV);
    AES_CBC_encrypt_buffer(& da_engine,& pass_word[0], pass_word.size());
    AES_init_ctx_iv(& da_engine, & my_KEKvec[0], IV_kek);
    paddingStrings(my_DEKvec);
    AES_CBC_encrypt_buffer(& da_engine,& my_DEKvec[0], my_DEKvec.size());

    while (fileExists(current_filename)){
        index++;
        current_filename = base_name + to_string(index) + extension;
    }
    ofstream vault_file(current_filename);
    
    if (vault_file.is_open()){
        
        for (int i = 0; i < 16; i++){
            vault_file << hex << setfill('0') << setw(2) << (int)salt[i];
        }
        vault_file<<"\n";
        
        for (int i = 0; i < 16; i++){
            vault_file << hex << setfill('0') << setw(2) << (int)IV_kek[i];
        }
        vault_file<<"\n";
        
        for (int i = 0; i < KEK_verify.size(); i++){
            vault_file << ver[i];
        }
        vault_file << "\n";
        
        for (int i = 0; i < my_DEKvec.size(); i++){
            vault_file << hex << setfill('0') << setw(2) << (int)my_DEKvec[i];
        }
        vault_file << "\n";
        vault_file << site << "|";
        for (int i = 0; i < 16; i++){
            vault_file << hex << setfill('0') << setw(2) << (int)IV[i];
        }
        vault_file << "|";
        for (int i = 0; i < pass_word.size(); i++){
            vault_file << hex << setfill('0') << setw(2) << (int)pass_word[i];
        }
        vault_file <<  "\n";
        vault_file.close();
    }
    cout << "Vault successfully created";
}

void adder(string pin, string site, string password, int vault_no){
    current_filename = base_name + to_string(vault_no) + extension;
    ifstream vault_file(current_filename);
    string current_line, current, next, ver, DEK_Iv_hex;
    AES_ctx da_engine;
    if (vault_file.is_open()){
        getline(vault_file, current_line);
        string salt_hex = current_line;
        string raw_salt = hexToRaw(salt_hex);
        
        string bs_string = arrayToStrings(pepper, sizeof(pepper)) + pin + raw_salt;
        current = bs_string;
        for (int i = 0; i < 100000; i++){
            picosha2::hash256_hex_string(current,next);
            current = next;
        }
        picosha2::hash256_hex_string(next, ver);
        vector <uint8_t> my_KEKvec = stringToArray(next);
        
        getline(vault_file, current_line);
        DEK_Iv_hex = current_line;
        
        getline(vault_file, current_line);
        
        if (current_line.find(ver) != string::npos){
            vector <uint8_t> DEC_IV = stringToArray(hexToRaw(DEK_Iv_hex));
            vector <uint8_t> password_vec = stringToArray(password);
            paddingStrings(password_vec);
            getline(vault_file, current_line);
            string enc_DEK = current_line;
            vector <uint8_t> enc_DEKvec = stringToArray(hexToRaw(enc_DEK));
            AES_init_ctx_iv(& da_engine,& my_KEKvec[0],& DEC_IV[0]);
            AES_CBC_decrypt_buffer(& da_engine,& enc_DEKvec[0], enc_DEKvec.size());
            removePadding(enc_DEKvec);
            uint8_t IV_new[16];
            generateSecureBytes(IV_new, 16);
            AES_init_ctx_iv(& da_engine,& enc_DEKvec[0], IV_new);
            AES_CBC_encrypt_buffer(& da_engine,& password_vec[0], password_vec.size());
            ofstream vault_file(current_filename, ios::app);
            if (vault_file.is_open()){
                vault_file << site << "|";
                for (int i = 0; i < 16; i++){
                    vault_file << hex << setfill('0') << setw(2) << (int)IV_new[i];
                }
                vault_file << "|";
                for (int i = 0; i < password_vec.size(); i++){
                    vault_file << hex << setfill('0') << setw(2) << (int)password_vec[i];
                }
            }
            cout << "Password successfully stored";
        }
        else cout << "Wrong PIN";
    }
}
void retriever(string pin, int vault_no){
    current_filename = base_name + to_string(vault_no) + extension;
    ifstream vault_file(current_filename);
    string current_line, current, next, ver, DEK_Iv_hex;
    AES_ctx da_engine;
    if (vault_file.is_open()){
        getline(vault_file, current_line);
        string salt_hex = current_line;
        string raw_salt = hexToRaw(salt_hex);
        
        string bs_string = arrayToStrings(pepper, sizeof(pepper)) + pin + raw_salt;
        current = bs_string;
        for (int i = 0; i < 100000; i++){
            picosha2::hash256_hex_string(current,next);
            current = next;
        }
        picosha2::hash256_hex_string(next, ver);
        vector <uint8_t> my_KEKvec = stringToArray(next);
        
        getline(vault_file, current_line);
        DEK_Iv_hex = current_line;
        
        getline(vault_file, current_line);
        
        if (current_line.find(ver) != string::npos){
            vector <uint8_t> DEC_IV = stringToArray(hexToRaw(DEK_Iv_hex));
            getline(vault_file, current_line);
            string enc_DEK = current_line;
            vector <uint8_t> enc_DEKvec = stringToArray(hexToRaw(enc_DEK));
            AES_init_ctx_iv(& da_engine,& my_KEKvec[0],& DEC_IV[0]);
            AES_CBC_decrypt_buffer(& da_engine,& enc_DEKvec[0], enc_DEKvec.size());
            removePadding(enc_DEKvec);
            string site, iv_hex, pass_hex;
            while (getline(vault_file, current_line)){
                stringCleaver(current_line, site, iv_hex, pass_hex);
                vector <uint8_t> IV_vec = stringToArray(hexToRaw(iv_hex));
                vector <uint8_t> pass_vec = stringToArray(hexToRaw(pass_hex));
                AES_init_ctx_iv(& da_engine,& enc_DEKvec[0],& IV_vec[0]);
                AES_CBC_decrypt_buffer(& da_engine,& pass_vec[0], pass_vec.size());
                removePadding(pass_vec);
                cout << site << " | ";
                for (int i = 0; i < pass_vec.size(); i++){
                    cout << pass_vec[i];
                }
                cout << '\n'; 
            }

        }
        else cout << "Wrong PIN";
    }

}

void deleter (int vault_no, string pin){
    current_filename = base_name + to_string(vault_no) + extension;
    ifstream vault_file(current_filename);
    string current_line, current, next, ver, DEK_Iv_hex;
    AES_ctx da_engine;
    if (vault_file.is_open()){
        getline(vault_file, current_line);
        string salt_hex = current_line;
        string raw_salt = hexToRaw(salt_hex);
        
        string bs_string = arrayToStrings(pepper, sizeof(pepper)) + pin + raw_salt;
        current = bs_string;
        for (int i = 0; i < 100000; i++){
            picosha2::hash256_hex_string(current,next);
            current = next;
        }
        picosha2::hash256_hex_string(next, ver);
        vector <uint8_t> my_KEKvec = stringToArray(next);
        
        getline(vault_file, current_line);
        DEK_Iv_hex = current_line;
        
        getline(vault_file, current_line);
        
        if (current_line.find(ver) != string::npos){
            vault_file.close();
            if(remove(current_filename.c_str()) == 0){
                std::cout << "Old vault completely wiped from the hard drive.\n";
            } else {
                std::cout << "Vault not found, or it is already deleted.\n";
            }
        }
        else cout << "Wrong PIN";
    }
}

int main(){
    cout << "Enter command:";
    string option;
    string User_PIN;
    int vault_no;
    cin >> option;
    if (option == "Local_vault-create"){
        string site_name, password;
        cout << "Enter the domain:";
        cin >> site_name;
        cout << "Enter the password:";
        cin >> password;
        vector <uint8_t>  pass_word;
        for (int i = 0; i < password.length(); i++){
            pass_word.push_back(password[i]);
        } 
        paddingStrings(pass_word);
        cout << "Decide your PIN:";
        cin >> User_PIN;
        creatingVault(site_name ,pass_word, User_PIN);
    }
    else if (option == "Local_vault-add"){
        cout << "Enter vault no:";
        cin >> vault_no;
        cout << "Enter PIN:";
        cin >> User_PIN;
        string new_pass, site;
        cout << "Enter the domain:";
        cin >> site;
        cout << "Enter the password:";
        cin >> new_pass;
        adder(User_PIN, site, new_pass, vault_no);
    }
    else if(option == "Local_vault-retrieve"){
        cout << "Enter vault no:";
        cin >> vault_no;
        cout << "Enter PIN:";
        cin >> User_PIN;
        retriever(User_PIN, vault_no);
    }
    else if (option == "Local_vault-delete"){
        cout << "Enter vault no:";
        cin >> vault_no;
        cout << "Enter PIN:";
        cin >> User_PIN;
        deleter(vault_no, User_PIN);
    }
    else if (option == "-help"){
        cout << "Commands List:" << endl << "Local_vault-create: To create a new vault" << endl << "Local_vault-add: to add a new entry" << endl << "Local_vault-retrieve: Retreive the info stored in the vaults" << endl << "Local_vault-delete: Delete the given vault";
    
    }
    else cout << "Wrong command. Type '-help' for list of commands.";
    
    
    return 0;
}