#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/sha.h>

// Function to generate a random salt
std::string generateSalt() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {  // 16 bytes for salt
        oss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    return oss.str();
}

// Function to hash a password with salt using SHA-256
#include <openssl/evp.h>

std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string input = password + salt;
    //unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("sha256");

    if (!md) {
        std::cerr << "Unknown message digest" << std::endl;
        exit(1);
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (i = 0; i < md_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
    }

    return ss.str();
}


// Function to authenticate a user
bool authenticateUser(const std::string& username, const std::string& password, const std::string& storedHash, const std::string& storedSalt) {
    std::string hashedInput = hashPassword(password, storedSalt);
    return hashedInput == storedHash;
}

int main() {
    // Simulated database of username, password hash, and salt
    std::ofstream database("passwords.txt");
    if (!database.is_open()) {
        std::cerr << "Error opening passwords.txt" << std::endl;
        return 1;
    }

    // Add sample user to the database
    std::string username = "user";
    std::string password = "password";
    std::string salt = generateSalt();
    std::string hashedPassword = hashPassword(password, salt);
    database << username << ":" << hashedPassword << ":" << salt << std::endl;
    database.close();

    // Simulated login attempt
    std::string inputUsername, inputPassword;
    std::cout << "Enter username: ";
    std::cin >> inputUsername;
    std::cout << "Enter password: ";
    std::cin >> inputPassword;

    // Read hashed password and salt from the file
    std::ifstream inputFile("passwords.txt");
    if (!inputFile.is_open()) {
        std::cerr << "Error opening passwords.txt" << std::endl;
        return 1;
    }
    std::string line;
    std::getline(inputFile, line);
    inputFile.close();

    std::istringstream iss(line);
    std::string storedUsername, storedHash, storedSalt;
    std::getline(std::getline(iss, storedUsername, ':'), storedHash, ':');
    std::getline(iss, storedSalt, ':');

    // Authenticate the user
    if (inputUsername == storedUsername && authenticateUser(inputUsername, inputPassword, storedHash, storedSalt)) {
        std::cout << "Authentication successful!" << std::endl;
    }
    else {
        std::cout << "Authentication failed!" << std::endl;
    }

    return 0;
}
