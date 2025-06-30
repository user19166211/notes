#include <iostream>
#include <mariadb/conncpp.hpp>
#include <cgicc/Cgicc.h>
#include <cgicc/HTTPHTMLHeader.h>
#include <cgicc/HTTPCookie.h>
#include <string>
#include <cgicc/CgiEnvironment.h>
#include <cgicc/HTTPRedirectHeader.h>

#include "functions.h"

using namespace std;
using namespace cgicc;

int main() {
        try {
        Cgicc cgi;

        // Connect to database
        unique_ptr<sql::Connection> conn = connectDB();
        if (!conn) {
            cout << HTTPHTMLHeader()
                 << "<!DOCTYPE html><head><title>Error</title></head>"
                 << "<body><p>Failed to connect to database.</p></body></html>" << endl;
            return 1;
        }
        // Get action parameter 
        form_iterator action = cgi.getElement("action");
        string action_value = (action != cgi.getElements().end()) ? **action : "";
        string sessionToken;
        int user_id = -1;
        string name;

        // handle session if user action is not login in or 2FA (OTP)
        if (action_value != "login" && action_value != "otp") {
            try {                               
                const CgiEnvironment& env = cgi.getEnvironment();
                if (!validateSession(conn.get(), cgi, user_id, sessionToken)) {
                    // Redirect to session expired page if session is invalid
                    cout << HTTPRedirectHeader("/session_expired.html");

                    return 0;
                }            
            } catch (const exception& e) {
                // handle cookie reading errors
                    cout << HTTPHTMLHeader()
                        << "<html><body><p>Error reading cookies: "
                        << e.what() << "</p></body></html>" << endl;
                    return 1;
                }
        }

    // Handle actions based on the action parameter value
        //login
        if (action_value.empty() || action_value == "login") {
            handleLogin(conn, cgi);
            
        } else if (action_value == "otp" ) {
            twoFactorAuthentication(conn, cgi);            
            
        //logged in
        }else if (action_value == "menu" && user_id != -1) {
            handleMenu(conn, cgi, user_id, sessionToken);
            //handleMenu(conn, cgi);
        }else if (action_value == "view_all_posts" && user_id != -1) {
            displayAllPosts(conn.get(), user_id);
        }else if (action_value == "view_content" && user_id != -1){
            int post_num = stoi(**cgi.getElement("post_num"));
            displayPostContent(conn.get(), post_num);
             
        }else if ((action_value == "uprate" || action_value == "downrate") && user_id != -1){
            int post_num = stoi(**cgi.getElement("post_num"));
            updateRating(conn.get(), post_num, action_value);

        }else if (action_value == "view_your_posts" && user_id != -1) {
            displayBlogByUserId(conn.get(), user_id);
      
        }else if (action_value == "edit" ) {
             int post_num = stoi(**cgi.getElement("post_num"));
             editPostContent(conn.get(), post_num);
         }else if (action_value == "update_post") {
             int post_num = stoi(**cgi.getElement("post_num"));
             form_iterator newContentInput = cgi.getElement("new_content");
             string newContent = (newContentInput != cgi.getElements().end()) ? **newContentInput : "";
             updateContent(conn.get(), post_num, escapeHTML(newContent));
        }else if (action_value == "add_post" && user_id != -1) {
            string title = escapeHTML(cgi("title"));
            string content = escapeHTML(cgi("content"));
            if (!title.empty() && !content.empty()){
                addPost(conn.get(), title, content, user_id);
            }else {
                //get new post input from user
                cout << HTTPRedirectHeader("/add_post.html") << endl;
                return 0;
            }
         //admin only
         }else if (action_value == "admin_access" && user_id != -1) {          
            displayAdmin(conn.get(), user_id);

         }else if (action_value =="add_account" && user_id != -1){
             //check if the user is admin)
            if (!ifAdmin(conn.get(), user_id)) {
                cout << HTTPRedirectHeader("/invalid_action.html");
                return 1;
            }else{
                string name = escapeHTML(cgi("name"));
                string email = escapeHTML(cgi("email"));
                string password = escapeHTML(cgi("password"));                
                if (!name.empty() && !password.empty() && !email.empty()){                
                    createAccount(conn.get(), name, email, password);
                }else{
                    //get new account input from admin
                    cout << HTTPRedirectHeader("/add_account.html") << endl;
                    return 0;
                }                    
            }
        }else if (action_value == "logout") {
            handleLogout(conn, user_id, sessionToken);                  
        }else {
            // handle unknown action (error)
            invalidAction(user_id);
        }        
    } catch (const exception& e) {
        // redirect to internal error page on exception
        cout << HTTPRedirectHeader("/internal_error.html") << endl;
        return 1;
    }
    return 0;
}
