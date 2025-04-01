#include "userManager.h"
#include <cstdlib>

#define SECRET_KEY "JBSWY3DPEHPK3PXP"

UserManager::UserManager() {
    userDatabase = make_unique<UserDatabase>();
	userDatabase->backupDatabase("data/backup/users.db");
}

UserManager::~UserManager() {
}

string UserManager::generatePassword() {
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int length = 8;

    random_device rd;                      // Thu thập dữ liệu ngẫu nhiên từ hệ thống
    mt19937 generator(rd());                // Khởi tạo bộ sinh số ngẫu nhiên
    uniform_int_distribution<int> dist(0, chars.size() - 1); // Tạo khoảng phân phối hợp lệ

    string password;
    for (int i = 0; i < length; ++i) {
        password += chars[dist(generator)]; // Lấy ký tự ngẫu nhiên từ tập `chars`
    }

    return password;
}

void UserManager::generateOTP() {
    char otp[7] = { 0 };
    OTPData data;
    totp_new(&data, SECRET_KEY, hmac_algo_sha1, getCurrentTime, 6, 45);
    totp_now(&data, otp);
    cout << "Ma OTP cua ban la: " << otp << endl;
    getCurrentTime();
}

bool UserManager::verifyOTP(const string& userOTP) {
    char otp[7] = { 0 };
    OTPData data;
    totp_new(&data, SECRET_KEY, hmac_algo_sha1, getCurrentTime, 6, 45);
    totp_now(&data, otp);
    cout << "Xin moi nhap OTP: " << userOTP << endl;
    getCurrentTime();
    return (userOTP == otp);
}

void UserManager::registerUser() {
    system("cls");
    string username, password, fullName, phoneNumber;

    cout << "\nDANG KY NGUOI DUNG" << endl;
    cout << "Nhap ten nguoi dung: ";
    cin >> username;

    if (userDatabase->userExists(username)) {
        cout << "Loi: Ten nguoi dung da ton tai!" << endl;
        return;
    }

    cout << "Nhap mat khau: ";
    cin >> password;

    cout << "Nhap ho va ten: ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');  // Đảm bảo xóa bộ đệm trước khi getline
    getline(cin, fullName);

    cout << "Nhap so dien thoai: ";
    cin >> phoneNumber;

    userDatabase->addUser(username, password, "user", fullName, phoneNumber, 0);

    cout << "Dang ky thanh cong!" << endl;
}

void UserManager::registerUserForOthers() {
    system("cls");
    string username, password = generatePassword(), fullName, phoneNumber;

    cout << "\nNHAN VIEN QUAN LY - TAO TAI KHOAN HO" << endl;
    cout << "Nhap ten nguoi dung moi: ";
    cin >> username;

    if (userDatabase->userExists(username)) {
        cout << "Loi: Ten nguoi dung da ton tai!" << endl;
        return;
    }

    cout << "Nhap ho va ten: ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');  // Đảm bảo xóa bộ đệm trước khi getline
    getline(cin, fullName);

    cout << "Nhap so dien thoai: ";
    cin >> phoneNumber;

    userDatabase->addUser(username, password, "user", fullName, phoneNumber, 1);

    cout << "Tao tai khoan thanh cong!\nMat khau: " << password << " (Bat buoc doi sau khi dang nhap)" << endl;
}

User UserManager::loginUser() {
    string username, password;
    cout << "Nhap ten nguoi dung: ";
    cin >> username;

    cout << "Nhap mat khau: ";
    cin >> password;

    if (!userDatabase->userExists(username)) {
        cout << "Nguoi dung khong ton tai!" << endl;
        return User{};  // Trả về user rỗng nếu không tồn tại
    }

    User user = userDatabase->getUser(username);

    if (!userDatabase->verifyPassword(password, user.password)) {
        cout << "Mat khau sai!" << endl;
        return User{};
    }

    if (user.mustChangePassword) {
        cout << "Ban can doi mat khau ngay lap tuc!" << endl;
        changePassword(username);
        return User{};
    }

    cout << "Dang nhap thanh cong!" << endl;

    if (user.role == "manager") {
        showManagerMenu(username);
    }
    else {
        showUserMenu(username);
    }

    return user;
}

void UserManager::changePassword(const string& username) {
    string newPassword, userOTP;

    cout << "Nhap mat khau moi: ";
    cin >> newPassword;

    generateOTP();
    cout << "Nhap ma OTP de xac nhan: ";
    cin >> userOTP;

    if (verifyOTP(userOTP)) {

        userDatabase->updateUserPassword(username, newPassword);
        userDatabase->updateMustChangePassword(username, 0);

        cout << "Doi mat khau thanh cong!" << endl;
    }
    else {
        cout << "Ma OTP khong dung! Huy doi mat khau." << endl;
    }
}

bool UserManager::loadUserInfo(const string& username, User& user) {
    if (!userDatabase->userExists(username)) {
        return false;
    }
    user = userDatabase->getUser(username);
    return true;
}

void UserManager::updateUserInfo(const string& username, User& user) {
    string newFullName, newPhoneNumber, userOTP;
    cout << "Nhap ho ten moi: ";
    getline(cin >> ws, newFullName);
    cout << "Nhap so dien thoai moi: ";
    getline(cin, newPhoneNumber);

    generateOTP();
    cout << "Nhap ma OTP de xac nhan: ";
    cin >> userOTP;

    if (verifyOTP(userOTP)) {
        
        userDatabase->updateUserInfo(username, newFullName, newPhoneNumber);

        cout << "Cap nhat thong tin thanh cong!" << endl;

        
        if (loadUserInfo(username, user)) {
            cout << "Thong tin moi: " << user.fullName << " - " << user.phoneNumber << endl;
        }
    }
    else {
        cout << "Ma OTP khong dung! Huy cap nhat." << endl;
    }
}

void UserManager::showManagerMenu(const string& username) {
    User manager = userDatabase->getUser(username);

    if (manager.role != "manager") {
        return;
    }

    int choice;
    do {
        cout << "\n=== MENU QUAN LY ===" << endl;
        cout << "Ho va ten: " << manager.fullName << endl;
        cout << "So dien thoai: " << manager.phoneNumber << endl;
        cout << "Vai tro: Quan tri vien" << endl;
        cout << "----------------------------" << endl;
        cout << "1. Tao tai khoan ho" << endl;
        cout << "2. Doi mat khau" << endl;
        cout << "3. Dang xuat" << endl;
        cout << "Chon: ";
        cin >> choice;

        switch (choice) {
        case 1:
            registerUserForOthers();
            break;
        case 2:
            changePassword(manager.username);
            break;
        case 3:
            cout << "Dang xuat thanh cong!" << endl;
            return;
        default:
            cout << "Lua chon khong hop le!" << endl;
        }
    } while (choice != 3);
}

void UserManager::showUserMenu(const string& username) {
    User user = userDatabase->getUser(username);

    int choice;
    do {
        system("cls");  // Nếu dùng Linux/Mac, thay bằng system("clear");
        cout << "\n=== MENU NGUOI DUNG ===" << endl;
        cout << "Ho va ten: " << user.fullName << endl;
        cout << "So dien thoai: " << user.phoneNumber << endl;
        cout << "Vai tro: " << user.role << endl;
        cout << "----------------------------" << endl;
        cout << "1. Doi mat khau" << endl;
        cout << "2. Thay doi thong tin" << endl;
        cout << "3. Dang xuat" << endl;
        cout << "Chon: ";
        cin >> choice;

        if (cin.fail()) {  // Xử lý lỗi nhập sai
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Lua chon khong hop le! Vui long nhap lai." << endl;
            continue;
        }

        switch (choice) {
        case 1:
            changePassword(user.username);
            user = userDatabase->getUser(username);  // Cập nhật lại thông tin sau khi đổi mật khẩu
            break;
        case 2:
            updateUserInfo(user.username, user);
            user = userDatabase->getUser(username);  // Cập nhật lại thông tin sau khi thay đổi thông tin
            break;
        case 3:
            cout << "Dang xuat thanh cong!" << endl;
            return;
        default:
            cout << "Lua chon khong hop le!" << endl;
        }
    } while (choice != 3);
}