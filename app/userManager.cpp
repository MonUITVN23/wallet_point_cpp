#include "userManager.h"
#include <cstdlib>

#define SECRET_KEY "JBSWY3DPEHPK3PXP"

UserManager::UserManager() {
    if (sqlite3_open("data/users.db", &db) != SQLITE_OK) {
        cerr << "Khong the ket noi SQLite!" << endl;
    }
    initializeDatabase();
	backupDatabase("data/users_backup.db");
    //startAutomaticBackup("data/users_backup.db", 300);
}

UserManager::~UserManager() {
    sqlite3_close(db);
}

void UserManager::backupDatabase(const string& backupPath) {
    const string dbPath = "data/users.db";
    filesystem::create_directories(filesystem::path(backupPath).parent_path());

    ifstream src(dbPath, ios::binary);
    ofstream dst(backupPath, ios::binary);

    if (!src.is_open() || !dst.is_open()) {
        cerr << "Error: Unable to open database file or backup file." << std::endl;
        return;
    }

    dst << src.rdbuf();

    src.close();
    dst.close();
}

void UserManager::startAutomaticBackup(const string& backupPath, int intervalSeconds) {
    thread([this, backupPath, intervalSeconds]() {
        while (true) {
            this_thread::sleep_for(chrono::seconds(intervalSeconds));
            backupDatabase(backupPath);
        }
        }).detach();
}

string UserManager::hashPassword(const string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool UserManager::verifyPassword(const string& password, const string& hashedPassword) {
    return hashPassword(password) == hashedPassword;
}

bool UserManager::userExists(const string& username) {
    string sql = "SELECT COUNT(*) FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    int count = 0;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    return count > 0;
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

void UserManager::initializeDatabase() {
    string sql = "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY, "
        "password TEXT, "
        "role TEXT, "
        "fullName TEXT, "
        "phoneNumber TEXT, "
        "mustChangePassword INTEGER DEFAULT 0);";
    sqlite3_exec(db, sql.c_str(), 0, 0, 0);

    string checkAdminSql = "SELECT COUNT(*) FROM users WHERE role='manager';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, checkAdminSql.c_str(), -1, &stmt, 0);

    if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 0) {
        string adminPassword = "admin123";  // Mật khẩu mặc định
        string hashedAdminPass = hashPassword(adminPassword); // Băm mật khẩu

        string insertAdminSql = "INSERT INTO users (username, password, role, fullName, phoneNumber, mustChangePassword) VALUES "
            "('admin', '" + hashedAdminPass + "', 'manager', 'Admin User', '0123456789', 0);";
        sqlite3_exec(db, insertAdminSql.c_str(), 0, 0, 0);
    }
    sqlite3_finalize(stmt);
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

void UserManager::registerUser() {
	system("cls");
    string username, password, fullName, phoneNumber;

    cout << "\nDANG KY NGUOI DUNG" << endl;
    cout << "Nhap ten nguoi dung: ";
    cin >> username;

    cout << "Nhap mat khau: ";
    cin >> password;
    string hashedPassword = hashPassword(password); // Hash mật khẩu

    cout << "Nhap ho va ten: ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Đảm bảo xóa bộ đệm trước khi getline
    getline(cin, fullName);

    cout << "Nhap so dien thoai: ";
    cin >> phoneNumber;

    // Câu lệnh SQL sử dụng prepared statement để tránh SQL Injection
    string sql = "INSERT INTO users (username, password, role, fullName, phoneNumber, mustChangePassword) VALUES (?, ?, 'user', ?, ?, 0);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hashedPassword.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, fullName.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, phoneNumber.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_DONE) {
            cout << "Dang ky thanh cong!" << endl;
        }
        else {
            cout << "Loi: Khong the dang ky nguoi dung!" << endl;
        }
    }
    else {
        cout << "Loi: Khong the thuc thi cau lenh SQL!" << endl;
    }

    sqlite3_finalize(stmt);
}

void UserManager::registerUserForOthers() {
	system("cls");
    string username, password = generatePassword(), fullName, phoneNumber;

    cout << "\nNHAN VIEN QUAN LY - TAO TAI KHOAN HO" << endl;
    cout << "Nhap ten nguoi dung moi: ";
    cin >> username;

    cout << "Nhap ho va ten: ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Xử lý bộ đệm trước khi getline
    getline(cin, fullName);

    cout << "Nhap so dien thoai: ";
    cin >> phoneNumber;

    string hashedPassword = hashPassword(password); // Hash mật khẩu trước khi lưu

    // Câu lệnh SQL sử dụng prepared statement để tránh SQL Injection
    string sql = "INSERT INTO users (username, password, role, fullName, phoneNumber, mustChangePassword) VALUES (?, ?, 'user', ?, ?, 1);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hashedPassword.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, fullName.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, phoneNumber.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_DONE) {
            cout << "Tao tai khoan thanh cong!\nMat khau: " << password << " (Bat buoc doi sau khi dang nhap)" << endl;
        }
        else {
            cout << "Loi: Khong the tao tai khoan!" << endl;
        }
    }
    else {
        cout << "Loi: Khong the thuc thi cau lenh SQL!" << endl;
    }

    sqlite3_finalize(stmt);
}

User* UserManager::loginUser() {
	system("cls");

    string username, password;
    cout << "\nDANG NHAP" << endl;
    cout << "Nhap ten nguoi dung: ";
    cin >> username;
    cout << "Nhap mat khau: ";
    cin >> password;

    // Truy vấn mật khẩu băm từ database
    string sql = "SELECT password, role, mustChangePassword FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            string dbHashedPassword = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            string role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            int mustChangePassword = sqlite3_column_int(stmt, 2);

            sqlite3_finalize(stmt);

            // Kiểm tra mật khẩu nhập vào có khớp với mật khẩu đã băm trong database không
            if (!verifyPassword(password, dbHashedPassword)) {
                cout << "Mat khau khong dung!" << endl;
                return nullptr;
            }

            // Tạo đối tượng user
            User* user = new User;
            user->username = username;
            user->role = role;
            user->mustChangePassword = mustChangePassword;

            cout << "Dang nhap thanh cong!" << endl;

            if (user->mustChangePassword) {
                cout << "Ban duoc yeu cau doi mat khau ngay lap tuc!" << endl;
                changePassword(username);
            }

            if (role == "manager") {
                showManagerMenu();
            }
            else {
                showUserMenu(username);
            }

            return user;
        }
    }

    cout << "Ten nguoi dung khong ton tai hoac sai mat khau!" << endl;
    sqlite3_finalize(stmt);
    return nullptr;
}

void UserManager::changePassword(const string& username) {
    string newPassword, userOTP;
    cout << "Nhap mat khau moi: ";
    cin >> newPassword;

    generateOTP();
    cout << "Nhap ma OTP de xac nhan: ";
    cin >> userOTP;

    if (verifyOTP(userOTP))
    {
        string hashedPassword = hashPassword(newPassword);
        string sql = "UPDATE users SET password = ? , mustChangePassword = 0 WHERE username = ?;";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, hashedPassword.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            cout << "Doi mat khau thanh cong!" << endl;
        }
        else {
            cout << "Loi khi doi mat khau!" << endl;
        }
    }
	else {
		cout << "Ma OTP khong dung! Huy doi mat khau." << endl;
        return;
	}
}

bool UserManager::loadUserInfo(const string& username, User& user) {
    string sql = "SELECT fullName, phoneNumber FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user.fullName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            user.phoneNumber = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            sqlite3_finalize(stmt);
            return true;
        }
    }
    sqlite3_finalize(stmt);
    return false;
}

User* UserManager::getUserInfo(const string& username) {
    User* user = new User();  // Cấp phát đối tượng User mới
    string query = "SELECT username, password, role, fullName, phoneNumber FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;

    // Chuẩn bị câu lệnh SQL
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        // Nếu tìm thấy người dùng, lấy dữ liệu
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user->username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            user->password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            user->role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            user->fullName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            user->phoneNumber = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        }
        else {
            // Không tìm thấy người dùng => Xóa bộ nhớ cấp phát
            cout << "Loi: Khong tim thay nguoi dung '" << username << "'!" << endl;
            delete user;
            user = nullptr;
        }

        sqlite3_finalize(stmt);
    }
    else {
        cout << "Loi SQLite khi truy van user!" << endl;
    }

    return user; // Trả về con trỏ User hoặc nullptr nếu không tìm thấy
}

void UserManager::updateUserInfo(const string& username, User& user) {
    string newFullName, newPhoneNumber, userOTP;
    cout << "Nhap ho ten moi: ";
    getline(cin >> ws, newFullName);
    cout << "Nhap so dien thoai moi: ";
    getline(cin, newPhoneNumber);

    // Gửi OTP để xác nhận
    generateOTP();
    cout << "Nhap ma OTP de xac nhan: ";
    cin >> userOTP;

    if (verifyOTP(userOTP)) {
        string sql = "UPDATE users SET fullName = ?, phoneNumber = ? WHERE username = ?";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, newFullName.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, newPhoneNumber.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) == SQLITE_DONE) {
                cout << "Cap nhat thong tin thanh cong!" << endl;
                // Tải lại thông tin ngay lập tức
                if (loadUserInfo(username, user)) {
                    cout << "Thong tin moi: " << user.fullName << " - " << user.phoneNumber << endl;
                }
            }
            else {
                cout << "Loi khi cap nhat thong tin!" << endl;
            }
        }
        else {
            cout << "Loi truy van SQL!" << endl;
        }
        sqlite3_finalize(stmt);
    }
    else {
        cout << "Ma OTP khong dung! Huy cap nhat." << endl;
    }
}

void UserManager::showManagerMenu() {
    User* manager = getUserInfo("admin");  // Lấy thông tin admin từ DB

    if (!manager) {  // Kiểm tra nếu không lấy được dữ liệu
        cout << "Loi: Khong the lay thong tin quan ly!" << endl;
        return;
    }

    int choice;
    do {
		system("cls");
        cout << "\n=== MENU QUAN LY ===" << endl;
        cout << "Ho va ten: " << manager->fullName << endl;
        cout << "So dien thoai: " << manager->phoneNumber << endl;
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
            changePassword(manager->username);
            break;
        case 3:
            cout << "Dang xuat thanh cong!" << endl;
            delete manager;  // Giải phóng bộ nhớ
            return;
        default:
            cout << "Lua chon khong hop le!" << endl;
        }
    } while (choice != 3);

    delete manager;  // Giải phóng bộ nhớ trước khi thoát
}

void UserManager::showUserMenu(const string& username) {
    User* user = getUserInfo(username);  // Lấy thông tin người dùng từ DB

    if (!user) {  // Kiểm tra nếu không lấy được dữ liệu
        cout << "Loi: Khong the lay thong tin nguoi dung!" << endl;
        return;
    }

    int choice;
    do {
		system("cls");
        cout << "\n=== MENU NGUOI DUNG ===" << endl;
        cout << "Ho va ten: " << user->fullName << endl;
        cout << "So dien thoai: " << user->phoneNumber << endl;
        cout << "Vai tro: Nguoi dung" << endl;
        cout << "----------------------------" << endl;
        cout << "1. Doi mat khau" << endl;
        cout << "2. Thay doi thong tin" << endl;
        cout << "3. Dang xuat" << endl;
        cout << "Chon: ";
        cin >> choice;

        switch (choice) {
        case 1:
            changePassword(user->username);
            break;
        case 2:
            updateUserInfo(user->username, *user);
            break;
        case 3:
            cout << "Dang xuat thanh cong!" << endl;
            delete user;  // Giải phóng bộ nhớ
            return;
        default:
            cout << "Lua chon khong hop le!" << endl;
        }
    } while (choice != 3);

    delete user;  // Giải phóng bộ nhớ trước khi thoát
}
