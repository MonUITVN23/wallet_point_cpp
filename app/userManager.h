#pragma once

#ifndef USERMANAGER_H
#define USERMANAGER_H

#include <iostream>
#include <string>
#include <map>
#include <memory>
#include <cotp.h>

#include "otp_utils.h"
#include "userDatabase.h"
#include "user.h"

using namespace std;

class UserManager {
private:
    unique_ptr<UserDatabase> userDatabase;
	string generatePassword();

public:
    UserManager();
    ~UserManager();

    bool verifyOTP(const string& userOTP);
    void generateOTP();

    void registerUser();
    void registerUserForOthers();
    User loginUser();
    bool loadUserInfo(const string& username, User& user);
    void showManagerMenu(const string& username);
    void showUserMenu(const string& user);
    void changePassword(const string& username);
    void updateUserInfo(const string& username, User& user); 
};

#endif