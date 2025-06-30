#include <iostream>
#include <mariadb/conncpp.hpp>
#include <cgicc/Cgicc.h>
#include <cgicc/HTTPHTMLHeader.h>
#include <cgicc/HTTPRedirectHeader.h>
#include <cgicc/CgiEnvironment.h>
#include <random>
#include <ctime>
#include <sstream>
#include <string>

//for hashing
#include <openssl/sha.h> // For SHA-256 hashing
#include <iomanip> // For std::setfill and std::setw
#include <sstream> 

using namespace std;
using namespace cgicc;

// Connect to the database
unique_ptr<sql::Connection> connectDB();

//SANITISE INPUT
string escapeHTML(const string& input);

//LOGIN, MENU, LOGOUT
void handleLogin(unique_ptr<sql::Connection>& conn, const Cgicc& cgi);
void handleMenu(unique_ptr<sql::Connection>& conn, const Cgicc& cgi, int user_id, const string& sessionToken);
void handleLogout(unique_ptr<sql::Connection>& conn, int user_id, const string& sessionToken);

//VERIFY USER
string hashPassword(const string& password);
int getUserId(sql::Connection* conn, const string& name, const string& password);


//2FA 
string getUserEmail(sql::Connection* conn, int user_id);
string generateOTP();
void sendEmail(const string& email, const string& otp);
int validateOTP(sql::Connection* conn, int user_id, const string& otp);
void storeOTP(sql::Connection* conn, int user_id, const string& otp);
void twoFactorAuthentication(unique_ptr<sql::Connection>& conn, const Cgicc& cgi);

//COOKIE
string generateSessionToken();
void setSessionCookie(sql::Connection* conn, int user_id);
void createSession(sql::Connection* conn, int user_id, const string& sessionToken);
void discardSession(sql::Connection* conn, int user_id, string sessionToken);

//CHECK SESSEION
int getUserIdFromSession(sql::Connection* conn, string sessionToken);
bool validateSession(sql::Connection* conn, const Cgicc& cgi, int& user_id, string& sessionToken);
void updateLastActivity(sql::Connection* conn, const string& sessionToken);
bool isLoggedInWithCookie(sql::Connection* conn, const string& sessionToken, int& user_id);



// ALL POSTS 
void displayAllPosts(sql::Connection* conn, int user_id);
void displayPostContent(sql::Connection* conn, int post_num);
int getRatingbyratingID(sql::Connection* conn, int post_num);
void updateRating(sql::Connection* conn, int post_num, string action_value);


//YOUR POST
void displayBlogByUserId(sql::Connection* conn, int userId);
void editPostContent(sql::Connection* conn, int user_id);
void updateContent(sql::Connection* conn, int post_num,string newContent);
void addPost(sql::Connection* conn, string title, string content, int user_id);


//ADMIN
bool ifAdmin(sql::Connection* conn, int user_id);
void displayAdmin(sql::Connection* conn, int user_id);
int createAccount(sql::Connection* conn, string name, string email,  string password);


//HTML
string loadHTMLFile(const string& filepath);
void replacePlaceholders(string& content, const map<string, string>& replacements);

//invalid action
void invalidAction(int user_id);
