#pragma once

#ifndef USERMANAGER_H
#define USERMANAGER_H

#include <iostream>
#include <string>
#include <map>
#include <sqlite3.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <limits>
#include <ctime>
#include <fstream>
#include <cotp.h>
#include <chrono>
#include <thread>
#include <filesystem>
#include "otp_utils.h"
#include <openssl/sha.h>
using namespace std;

struct User {
    string username;
    string password;
    string role;
    string fullName;
    string phoneNumber;
    int mustChangePassword;
};

class UserManager {
private:
    sqlite3* db;
    void initializeDatabase();
    string generatePassword();
    string hashPassword(const string& password); 
    bool userExists(const string& username); 
	bool verifyPassword(const string& password, const string& hashedPassword); 
public:
    UserManager();
    ~UserManager();
    void backupDatabase(const std::string& backupPath);
    void startAutomaticBackup(const std::string& backupPath, int intervalSeconds);
    void registerUser();
    void registerUserForOthers();
    User* loginUser();
	bool loadUserInfo(const string& username, User& user);
    void showManagerMenu();
    void showUserMenu(const string& user);
    void changePassword(const string& username);
	User* getUserInfo(const string& username);
    void updateUserInfo(const string& username, User& user);
    bool verifyOTP(const string& userOTP);
    void generateOTP();
};

#endif
