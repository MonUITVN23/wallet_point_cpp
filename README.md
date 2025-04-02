User Management & Wallet System
This project implements a complete user management system with wallet functionality. It provides features for user registration, login with OTP-based verification, admin-driven pending changes that require confirmation, wallet management, and transaction recording.
Overview
•	User Management:
Users can register, log in, and update their profile (name, phone number). Password changes and profile updates require OTP confirmation for added security.
•	Admin Functionality:
Administrators (managers) can create user accounts with a system-generated password. They can also update other users’ information. Updates made on behalf of users are stored as pending changes until confirmed via OTP.
•	OTP Authentication:
OTP codes are generated using the TOTP algorithm with OpenSSL’s HMAC-SHA1 implementation. The OTP is used for sensitive operations such as fund transfers, password changes, and confirming pending profile updates.
•	Wallet & Transaction Management:
Each user is associated with a wallet where they receive initial points during account creation. The wallet manager provides functionality for checking balances, transferring points between wallets, and recording transactions.
•	Backup & Database:
The application uses SQLite to store users, wallets, and pending change information. An automatic backup feature is included to save a copy of the user database.
Features
•	Registration:
•	Standard registration for new users.
•	Admin-led registration for creating new user accounts with auto-generated passwords.
•	Login & Security:
•	Password authentication (using SHA-256 hashed passwords).
•	Mandatory password change when flagged.
•	OTP verification for profile updates and fund transfers.
•	Pending change display during login for user confirmation.
•	Wallet Management:
•	Creation of a dedicated wallet for each user.
•	Point-based transactions between users.
•	Master wallet deduction when funds are allocated.
•	Admin Menus:
•	Manage home accounts.
•	Update user information (with OTP-based pending change confirmation).
•	Change personal passwords.
Requirements
•	C++20 compiler (Visual Studio recommended)
•	SQLite3 library for database operations
•	OpenSSL library for OTP functionality
•	Standard C++ libraries
Build Instructions
1.	Clone the Repository:
Clone this repository onto your local machine.
2.	Dependencies:
Ensure SQLite3 and OpenSSL libraries are installed and correctly linked in your Visual Studio project settings.
3.	Compile:
Open the solution in Visual Studio and build the project. The project is configured to use C++20 features.
Usage Instructions
1.	Run the Application:
Execute the compiled binary. The interface will be displayed in the integrated console.
2.	User Flows:
•	Registration:
•	Choose the registration option and follow prompts for account details.
•	Login:
•	Input username and password. If any pending change exists, the new details are displayed and an OTP is requested.
•	Admin Functions:
•	Managers can create new user accounts, update user details, and execute wallet-based operations.
•	Wallet Transactions:
•	Use the interface for transferring points and viewing transaction history.
3.	OTP Verification:
The system displays a one-time password in the console. Enter that OTP to confirm sensitive operations.
Project Structure
•	app/userManager.cpp:
Contains the implementation for user-related functionalities including registration, login, OTP generation/verification, and admin/user menus.
•	app/userDatabase.cpp:
Manages user storage, password hashing, pending changes, backups, and SQLite database interactions.
•	app/walletManager.cpp:
Implements wallet creation, balance management, point transfers, and integration with SQLite.
•	app/otp_utils.cpp:
Provides functions for generating and verifying OTP using OpenSSL’s HMAC-SHA1 and current system time.
•	Other Files:
Additional project's header files, transaction manager, and utility modules are included as needed.
Notes
•	The system is primarily developed in Vietnamese and English. Prompts and messages may appear in Vietnamese.
•	OTP generation uses the TOTP algorithm with a hard-coded secret key (configurable as needed for production).
•	The application includes a backup mechanism to duplicate the SQLite database to a specified directory.
--------------------------------------------------
