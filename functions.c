#include "functions.h"

// Connect to the database
unique_ptr<sql::Connection> connectDB() {
    sql::Driver* driver = sql::mariadb::get_driver_instance();
    const string db_url = "jdbc:mariadb://localhost:3306/notes";
    
    sql::Properties properties({
        {"user", "db_user"}, {"password", "malware"}});
    
    unique_ptr<sql::Connection> conn(driver->connect(db_url, properties));
    cerr << "Connected to the database" << endl;
    return conn;
}

// == sanitise inputs by replacing characters to  HTML entities
string escapeHTML(const string& input) {
    string output;
    for (char c : input) {
        switch (c) {
            case '&': output += "&amp;"; break;
            case '<': output += "&lt;"; break;
            case '>': output += "&gt;"; break;
            case '"': output += "&quot;"; break;
            case '\'': output += "&#39;"; break;
            default: output += c;
        }
    }
    return output;
}


// === Handle Login ===
// login process (verifiy credentials, and sends an OTP for verification)
void handleLogin(unique_ptr<sql::Connection>& conn, const Cgicc& cgi) {
    //sanitise user inputs
    string name = escapeHTML(cgi("name"));
    string password = escapeHTML(cgi("password"));

    // check if user provided both name and password
    if (!name.empty() && !password.empty()) {
        int user_id = getUserId(conn.get(), name, password);
        
        //if the user is validated (have valid user id)
        if (user_id != -1) {
            // generate and send otp to the user's email(spool.txt)
            string otp = generateOTP();
            string email = getUserEmail(conn.get(), user_id);  // Function to get the email address based on user_id
            sendEmail(email, otp);

            // store the otp in the database
            storeOTP(conn.get(), user_id, otp);

            // process the HTML file to get the otp input
            string filePath = "/var/www/html/enter_otp.html";  // Path to the external HTML file
            string htmlContent = loadHTMLFile(filePath);
            
            if (htmlContent.empty()) {
                cerr << "Error: Unable to load HTML file at " << filePath << endl;
                return;
            }

            map<string, string> replacements = {
                {"user_id", to_string(user_id)}  // Replace {{user_id}} in the HTML file with the actual data
            };
            replacePlaceholders(htmlContent, replacements);

            // output the modified HTML content
            cout << "Content-Type: text/html\r\n\r\n";
            cout << htmlContent;
        } else {
            // if name or password is wrong redirect to login page with error message
            cout << HTTPRedirectHeader("/errorLogin.html") << endl;
        }
    } else {
        cout << HTTPRedirectHeader("/login.html") << endl;
    }
}

// check if a user is an admin
bool ifAdmin(sql::Connection* conn, int user_id) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT is_admin FROM users WHERE ID = ?"));
        pstmt->setInt(1, user_id);
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
            return res->getInt("is_admin") == 1;
        } else {
            cerr << "Error: User not found." << endl;
            return false;
        }
    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        return false;
    }
}

//function menu - display menu based on their role
void handleMenu(unique_ptr<sql::Connection>& conn, const Cgicc& cgi, int user_id, const string& sessionToken) {    
    // get the user's name and if they are admin or not from the database
    string userName;
    int admin;
    string filePath;
    
    try {
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement( "SELECT name FROM users WHERE ID = ?"));
        pstmt->setInt(1, user_id);
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) {
            userName = res->getString("name");  
            //admin = res->getInt("is_admin");
        } else {
            cerr << "Error: User not found." << endl;
            return;
        }
    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        return;
    }

    // display the admin html to admin, basic menu html to the non admin 
    bool isAdmin = ifAdmin(conn.get(), user_id);
    if (isAdmin){
         filePath = "/var/www/html/menu_admin.html"; 
    }else{
         filePath = "/var/www/html/menu.html"; 
    }
    
    string htmlContent = loadHTMLFile(filePath);
    if (htmlContent.empty()) {
        cerr << "Error: Unable to load menu.html file" << endl;
        return;
 
        
    }
    
    // Replace  {{name}}  with the user's name
    map<string, string> replacements;
    replacements["name"] = userName;
    
    // Replace placeholders in the HTML 
    replacePlaceholders(htmlContent, replacements);
    
    cout << "Content-type: text/html\r\n\r\n";
    cout << htmlContent;
}

// Function logout
// clearing the session token and redirecting to the login page
void handleLogout(unique_ptr<sql::Connection>& conn, int user_id, const string& sessionToken) {
    // invalidate the user's session by clearing the session token cookie
    HTTPCookie cookie("sessionToken", "");
    cookie.setPath("/");
    cookie.setMaxAge(0);
    cout << HTTPHTMLHeader().setCookie(cookie) << endl;

    // remove the session from the database  
    discardSession(conn.get(), user_id, sessionToken);
    cout << "<html><head><meta http-equiv='refresh' content='0; URL=/cgi-bin/main.cgi?action=login'></head></html>";
}

//password encryption
string hashPassword(const string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);

    ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    //return hased password
    return ss.str();
}

// === authentication (return user id when the name&password is correct
int getUserId(sql::Connection* conn, const string& name, const string& password) {
    // hash the password to check if it matches the password in the database
    string hashedPassword = hashPassword(password); 

    try{
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT ID FROM users WHERE name = ? AND password = ?"));
        pstmt->setString(1, name);     
        pstmt->setString(2, hashedPassword); 
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
            return res->getInt("ID");
        } 
    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
    }
    // return -1 if credentials are wrong
    return -1;
}


// == get users email for 2FA authentication
string getUserEmail(sql::Connection* conn, int user_id) {
    string email;
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("SELECT email FROM users WHERE ID = ?"));
        pstmt->setInt(1, user_id);     
        
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
            email = res->getString("email"); // Return email if found
        } 
    } 
    catch (const sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
    }

    return email; // Return empty string if no email found or an error occurred
}

//generate one time password for two factor authentication (6digit)
string generateOTP() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(100000, 999999);
    return to_string(dist(gen));
}

//send otp to email (spool.txt)
void sendEmail(const string& email, const string& otp) {
    ofstream mailSpool("/var/mail/spool.txt", ios::app);
    if (!mailSpool) {
        cerr << "Error: Could not write to /var/mail/spool.txt" << endl;
        return;
    }

    mailSpool << "To: " << email << "\n";
    mailSpool << "Subject: Your OTP Code\n";
    mailSpool << "Body: Your OTP code is " << otp << "\n\n";
    mailSpool.close();
}

// store otp to code table ( store one otp pser user)
void storeOTP(sql::Connection* conn, int user_id, const string& otp) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT INTO code (user_id, code) VALUES (?, ?) ON DUPLICATE KEY UPDATE code = VALUES(code)"));
        pstmt->setInt(1, user_id);
        pstmt->setString(2, otp);
        pstmt->executeUpdate();
        
    } 
    catch (const sql::SQLException& e) {
        cerr << "Error updating OTP: " << e.what() << endl;
    }
}
        
//check if otp is in the table      
int validateOTP(sql::Connection* conn, int user_id, const string& otp) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt( conn->prepareStatement("SELECT user_id FROM code WHERE user_id = ? AND code = ? "));
        pstmt->setInt(1, user_id);
        pstmt->setString(2, otp);
        
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            return res->getInt("user_id"); // OTP exists return user id
        }
    } 
    catch (const sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
    }
    return -1; // OTP does not exist or query failed
}


// === 2FA (if validates set cookie)
void twoFactorAuthentication(unique_ptr<sql::Connection>& conn, const Cgicc& cgi) {
    string otp = escapeHTML(cgi("otp"));
    
    int user_id = -1;
    try {
        user_id = stoi(cgi("user_id"));
    } catch (const exception& e) {
        cout << HTTPRedirectHeader("/invalid_otp.html") << endl;
        return;
    }

    if (!otp.empty()) {
        int valid_user_id = validateOTP(conn.get(), user_id, otp);
        
        if (valid_user_id != -1) {
            // if otp is valid, create session and set cookie
            setSessionCookie(conn.get(), user_id);
        } else {
            // Invalid: redirect to error page
            cout << HTTPRedirectHeader("/invalid_otp.html") << endl;
        }
    } else {
        // redirect to login page
        cout << HTTPRedirectHeader("/login.html") << endl;
    }
}

//generate random 32 digits number (string) for token
string generateSessionToken() {
    static random_device rd;
    static mt19937 engine(rd());
    static uniform_int_distribution<int> dist(0, 61); // 0-61 for (A-Z, a-z, 0-9)
    string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    string token;
     for (int i = 0; i < 32; ++i) { // 32-character session token
         token += chars[dist(engine)];
     }

    return token;
}


// crete session token and set cookie
void setSessionCookie(sql::Connection* conn, int user_id) {
    string sessionToken = generateSessionToken();
    createSession(conn, user_id, sessionToken);

    // set the session token as a cookie
    HTTPCookie sessionCookie("sessionToken", sessionToken);
    sessionCookie.setPath("/");
    sessionCookie.setMaxAge(1800); // Session valid for 30 minutes
    sessionCookie.setSecure(true); // Use HTTPS only
    
    cout << HTTPHTMLHeader().setCookie(sessionCookie) << endl;
    cout << "<html><head><meta http-equiv='refresh' content='0; URL=/cgi-bin/main.cgi?action=menu'></head></html>";
}

//create the session in the session table
void createSession(sql::Connection* conn, int user_id, const string& sessionToken) {
	try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT INTO sessions (user_id, session_token, created_at) VALUES (?, ?, NOW())"));
        pstmt->setInt(1, user_id);
        pstmt->setString(2, sessionToken);
        pstmt->executeUpdate();

    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        cout << "<p style='color: red;'>Failed to create session. Please try again later.</p>";
    }
}

//remove the session from table
void discardSession(sql::Connection* conn, int user_id, string sessionToken) {
	try {
        // Prepare the DELETE statement to remove the session
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("DELETE FROM sessions WHERE user_id = ? AND session_token = ?"));

        pstmt->setInt(1, user_id);
        pstmt->setString(2, sessionToken);

        int rowsAffected = pstmt->executeUpdate();
        
        if (rowsAffected > 0) {
            cout << "<p>Session successfully discarded.</p>"
                    << "<a href='http://localhost/cgi-bin/main.cgi?action=login'>Log in</a>";
        } else {
            cout << "<p style='color: red;'>No session found to discard.</p>";
        }

    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        cout << "<p style='color: red;'>Failed to discard session. Please try again later.</p>";
    }
}

//get user id from valid session
int getUserIdFromSession(sql::Connection* conn, string sessionToken) {    
    try{
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT user_id FROM sessions WHERE sessionToken = ? "));
        pstmt->setString(1, sessionToken);     
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
            return res->getInt("user_id");
        } 
    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
    }
    return -1;
}

//check if the session is still valid
bool validateSession(sql::Connection* conn, const Cgicc& cgi, int& user_id, string& sessionToken) {
    const CgiEnvironment& env = cgi.getEnvironment();
    for (const auto& cookie : env.getCookieList()) {
        if (cookie.getName() == "sessionToken" && !cookie.getValue().empty()) {
            
               // return true;
            sessionToken = cookie.getValue();
            updateLastActivity(conn, sessionToken);
            user_id = getUserIdFromSession(conn, sessionToken);
            return isLoggedInWithCookie(conn, sessionToken, user_id);
        }
    }
    
    return false;
}

//update the session created time to now (used when any action is made by user -> expiry time +30 min)
void updateLastActivity(sql::Connection* conn, const string& sessionToken) {
    try {
        unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement("UPDATE sessions SET created_at = CURRENT_TIMESTAMP WHERE session_token = ?"));
        
        stmt->setString(1, sessionToken);
        stmt->executeUpdate();
    } catch (const sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
    }
}


//verify the user is logged in
bool isLoggedInWithCookie(sql::Connection* conn, const string& sessionToken, int& user_id) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("SELECT user_id FROM sessions WHERE session_token = ?"));
        pstmt->setString(1, sessionToken);

        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            user_id = res->getInt("user_id");
            return true;
        }
        return false;
    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        return false;
    }
}


// == HTML
void replacePlaceholders(string& content, const map<string, string>& replacements) {
    for (const auto& pair : replacements) {
        string placeholder = "{{" + pair.first + "}}";
        size_t pos = content.find(placeholder);
        while (pos != string::npos) {
            content.replace(pos, placeholder.size(), pair.second);
            pos = content.find(placeholder, pos + pair.second.size());
        }
    }
}

string loadHTMLFile(const string& filepath) {
    ifstream file(filepath);
    if (!file) {
        cerr << "Error: Could not open file: " << filepath << endl;
        return "";
    }

    stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}


//display all post
void displayAllPosts(sql::Connection* conn, int user_id){    
    
    if (user_id <= 0) {
        cerr << "Error: Invalid user ID" << endl;
        return;
    }
    
    //use html template to display posts
    string filePath = "/var/www/html/all_posts.html"; 
    string htmlContent = loadHTMLFile(filePath);
    if (htmlContent.empty()) {
        cerr << "Error: Unable to load HTML file" << endl;;
        return;
    }
    
    // Generate the posts table ( dynamically)
    string userPostRows;
    try {
        
        unique_ptr<sql::Statement> stmt(conn->createStatement());
        unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT post_num, user_id, title, content, created FROM blog_posts"));
    
        
        while (res->next()) {
            int postNum = res->getInt("post_num");
            
            userPostRows += "<tr>";
            userPostRows += "<td>" + to_string(postNum) + "</td>";
            userPostRows += "<td>" + to_string(res->getInt("user_id")) + "</td>";
            
        // click title to see the content
            userPostRows += "<td>";
            userPostRows += "<form method='GET' action=''>";
            userPostRows += "<input type='hidden' name='action' value='view_content'>";
            userPostRows += "<input type='hidden' name='post_num' value='" + to_string(postNum) + "'>";
            userPostRows += "<button type='submit' class='button'>"+  res->getString("title") +"</button>";
            userPostRows += "</form>";
            userPostRows += "</td>";            
            
            userPostRows += "<td>" + res->getString("created") + "</td>";
            userPostRows += "<td>" + to_string(getRatingbyratingID(conn, postNum)) + "</td>";
            
            userPostRows += "</tr>";
                }
    } catch (sql::SQLException& e) {
            cerr << "SQL Error: " << e.what() << endl;
    }
        
    // replace with the data retrieved by the database
    map<string, string> replacements;
     replacements["BLOG_POSTS"] = userPostRows; 
 
     replacePlaceholders(htmlContent, replacements);
    
    // Output the final HTML content
    cout << "Content-type: text/html\r\n\r\n";
    cout << htmlContent;
}
    
    
//display the content of the selected post, rating button
void displayPostContent(sql::Connection* conn, int post_num) {    
    if (post_num <= 0) {
        cerr << "Error: Post does not exist" << endl;
        return;
    }
    
    // load html template 
    string filePath = "/var/www/html/post_content.html"; 
    string htmlContent = loadHTMLFile(filePath);
    if (htmlContent.empty()) {
        cerr << "Error: Unable to load HTML file" << endl;;
        return;
    }
        
    try {
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement(
            "SELECT post_num, user_id, title, content, created FROM blog_posts WHERE post_num = ? LIMIT 1"
        ));
        pstmt->setInt(1, post_num);
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) {
            map<string, string> replacements;
               replacements["title"] = res->getString("title");
                replacements["content"] = res->getString("content");
                replacements["created"] = res->getString("created");
                replacements["uprate"] = to_string(post_num);
                replacements["downrate"] = to_string(post_num);
       
            // Replace placeholders in the HTML content
            replacePlaceholders(htmlContent, replacements);
        } else {
            cout << "Content-type: text/html\r\n\r\n";
            cout << "<p>Post not found</p>";
            return;
        }

    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        cout << "Content-type: text/html\r\n\r\n";
        cout << "<p>SQL Error: " << e.what() << "</p>";
        return;
    }

    // Send the final HTML content
    cout << "Content-type: text/html\r\n\r\n";
    cout << htmlContent;
}


//get the rating of each blog post (by post number)
int getRatingbyratingID(sql::Connection* conn, int post_num){
    unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT rating FROM ratings WHERE post_num = ? "));
    pstmt->setInt(1, post_num);     
    
    unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
    
    if (res->next()) {
        return res->getInt("rating");
    } else {
        return -1;
    }
}


//uprate or downrate the rating
void updateRating(sql::Connection* conn, int post_num, string action_value){
    if (post_num <= 0 ) {
        cout << "Content-type: text/html\r\n\r\n";
        cout << "<p>Error: Invalid post number or empty content.</p>";
        return;
    }

    try {
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT rating FROM ratings WHERE post_num = ?"));
        pstmt->setInt(1, post_num);
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
                
                int currentRating = res->getInt("rating");
                
                //Update rating based on action
                int newRating = (action_value == "uprate") ? currentRating + 1 : currentRating - 1;
                
                unique_ptr<sql::PreparedStatement> updatePstmt(conn->prepareStatement("UPDATE ratings SET rating = ? WHERE post_num = ?"));
                updatePstmt->setInt(1, newRating);
                updatePstmt->setInt(2, post_num);
                        
                int rowsAffected = updatePstmt->executeUpdate();

                if (rowsAffected > 0) {
                    cout << HTTPRedirectHeader("/updated_rating.html");
                } else {
                    cout << HTTPRedirectHeader("/rating_failed.html");
                }
        }

    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        cout << "Content-type: text/html\r\n\r\n";
        cout << "<p>SQL Error: " << e.what() << "</p>";
    }
}

//display the blog by user
void displayBlogByUserId(sql::Connection* conn, int user_id) {
    
    if (user_id <= 0) {
        cerr << "Error: Invalid user ID" << endl;
        return;
    }    
    
    string filePath = "/var/www/html/user_post.html"; 
    string htmlContent = loadHTMLFile(filePath);
    if (htmlContent.empty()) {
        cerr << "Error: Unable to load HTML file" << endl;;
        return;
    }
    
    // Generate the user table ( dynamically)
    string userPostRows;
    try {
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT post_num, user_id, title, content, created FROM blog_posts WHERE user_id = ?"));
        pstmt->setInt(1, user_id);
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        while (res->next()) {
            int postNum = res->getInt("post_num");
            
            userPostRows += "<tr>";
            userPostRows += "<td>" + to_string(postNum) + "</td>";
            userPostRows += "<td>" + to_string(res->getInt("user_id")) + "</td>";
            userPostRows += "<td>" + res->getString("title") + "</td>";
            userPostRows += "<td>" + res->getString("content") + "</td>";
            userPostRows += "<td>" + res->getString("created") + "</td>";
            
        // edit button for each post
            userPostRows += "<td>";
            userPostRows += "<form method='GET' action='/cgi-bin/main.cgi'>";
            userPostRows += "<input type='hidden' name='action' value='edit'>";
            userPostRows += "<input type='hidden' name='post_num' value='" + to_string(postNum) + "'>";
            userPostRows += "<button type='submit' class='button'>Edit</button>";
            userPostRows += "</form>";
            userPostRows += "</td>";
            
            userPostRows += "</tr>";
        }
    } catch (sql::SQLException& e) {
            cerr << "SQL Error: " << e.what() << endl;
    }
                
     map<string, string> replacements;
     replacements["USER_BLOG"] = userPostRows; 
 
     replacePlaceholders(htmlContent, replacements);
    
    // Output the final HTML content
    cout << "Content-type: text/html\r\n\r\n";
    cout << htmlContent;
}


//edit post (view)
void editPostContent(sql::Connection* conn, int post_num) {    
    if (post_num <= 0) {
        cerr << "Error: Invalid user ID" << endl;
        return;
    }    
    
    string filePath = "/var/www/html/edit.html"; 
    string htmlContent = loadHTMLFile(filePath);
    if (htmlContent.empty()) {
        cerr << "Error: Unable to load HTML file" << endl;;
        return;
    }
    
    try {
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement( "SELECT post_num, user_id, title, content, created FROM blog_posts WHERE post_num = ?"));
        pstmt->setInt(1, post_num);
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) {
            map<string, string> replacements;
            replacements["content"] = res->getString("content");
            replacements["post_num"] = to_string(post_num);

            replacePlaceholders(htmlContent, replacements);
        } else {
            cout << "Content-type: text/html\r\n\r\n";
            cout << "<p>Post not found</p>";
            return;
        }

    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        cout << "Content-type: text/html\r\n\r\n";
        cout << "<p>SQL Error: " << e.what() << "</p>";
        return;
    }

    // Send the final HTML content
    cout << "Content-type: text/html\r\n\r\n";
    cout << htmlContent;
}



//update to the edited post (process)
void updateContent(sql::Connection* conn, int post_num, string newContent) {           
    if (post_num <= 0 || newContent.empty()) {
        cout << "Content-type: text/html\r\n\r\n";
        cout << "<p>Error: Invalid post number or empty content.</p>";
        return;
    }

    try {
        unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("UPDATE blog_posts SET content = ? WHERE post_num = ?"));
        pstmt->setString(1, newContent);
        pstmt->setInt(2, post_num);
        
        int rowsAffected = pstmt->executeUpdate();

        if (rowsAffected > 0) {
            //update success
            cout << HTTPRedirectHeader("/updated.html");
        } else {
            // If no rows are affected, provide an error message
            cout << HTTPRedirectHeader("/update_failed.html");
        }

    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        cout << "Content-type: text/html\r\n\r\n";
        cout << "<p>SQL Error: " << e.what() << "</p>";
    }
}



//create new post
void addPost(sql::Connection* conn, string title, string content, int user_id){
        try{
             if (!title.empty() && !content.empty() && user_id != -1) {
 
                 // Insert into database
                 unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement(
                             "INSERT INTO blog_posts (user_id, title, content, created) "
                             "VALUES (?, ?, ?, NOW())"));
                 pstmt->setInt(1, user_id);
                 pstmt->setString(2, title);
                 pstmt->setString(3, content);
 
                 int rowsAffected = pstmt->executeUpdate();

                    if (rowsAffected > 0) {
                        cout << HTTPRedirectHeader("/post_added.html");
                    } else {
                        cout << HTTPRedirectHeader("/postcreation_failed.html");
                    }
             }
        } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        cout << "Content-type: text/html\r\n\r\n";
        cout << "<p>SQL Error: " << e.what() << "</p>";
        }   
}
    
//===ADMIN ACCESS

//if admin selects the admin view, display the user info and create account button
void displayAdmin(sql::Connection* conn, int user_id){
    //check if the user is admin)
    if (!ifAdmin(conn, user_id)) {
        cout << HTTPRedirectHeader("/invalid_action.html");
        return;
    }
    
    string filePath = "/var/www/html/admin.html"; 
    string htmlContent = loadHTMLFile(filePath);
    if (htmlContent.empty()) {
        cerr << "Error: Unable to load HTML file" << endl;
        return;
    }

    string userRows;
    try {
        unique_ptr<sql::Statement> stmt(conn->createStatement());
        unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT ID, name, email, password, is_admin FROM users"));
        
        while (res->next()) {
            userRows += "<tr>";
            userRows += "<td>" + to_string(res->getInt("ID")) + "</td>";
            userRows += "<td>" + res->getString("name") + "</td>";
            userRows += "<td>" + res->getString("email") + "</td>";
            //userRows += "<td>" + string(res->getInt("is_admin") == 1 ? "Yes" : "No") + "</td>";
            userRows += "</tr>";
        }
    } catch (sql::SQLException& e) {
        cerr << "SQL Error: " << e.what() << endl;
        return;
    }

    map<string, string> replacements;
    replacements["USER_TABLE_ROWS"] = userRows; 

    replacePlaceholders(htmlContent, replacements);

    cout << "Content-type: text/html\r\n\r\n";
    cout << htmlContent;
}

//add the new account to users table (id(auto), name, email, pashed pass, is_admin(no))
int createAccount(sql::Connection* conn, string name, string email, string password){
    
    if (!name.empty() && !password.empty() && !email.empty()) {
        //encryption
            string hashedPassword = hashPassword(password);
        
            try{
                // Insert into database
                unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement(
                            "INSERT INTO users (name, email, password, is_admin) "
                            "VALUES (?, ?, ?, 0)"));

                pstmt->setString(1, name);
                pstmt->setString(2, email);
                pstmt->setString(3, hashedPassword);
                
                int rowsAffected = pstmt->executeUpdate();

                if (rowsAffected > 0) {
                    cout << HTTPRedirectHeader("/account_created.html");
                } else {
                    cout << HTTPRedirectHeader("/accountcreation_failed.html");
                }
                
    
            } catch (sql::SQLException& e) {
                    cerr << "SQL Error: " << e.what() << endl;
                    cout << "<p style='color:red;'>Error creating user. Please try again later.</p>";
            } 
        }else {
            cout << "<p'>All fields are required.</p>";
        }
    cout << "</body></html>";
    return 0;
}


void invalidAction(int user_id){
     if (user_id <= 0) {
        cerr << "Error: Invalid user ID" << endl;
        return;
    }
    
    ifstream file("/var/www/html/invalid_action.html");
    if (!file) {
        cerr << "Error: Could not open invalid_action.html" << endl;
        return;
    }
 
    stringstream buffer;
    buffer << file.rdbuf();
    string htmlContent = buffer.str();
    file.close();
    
}
