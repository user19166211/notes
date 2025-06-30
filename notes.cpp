#include <iostream>
#include <mariadb/conncpp.hpp>
#include <cgicc/Cgicc.h>
#include <cgicc/HTTPHTMLHeader.h>

using namespace std;
using namespace cgicc;

//connect to the database
unique_ptr<sql::Connection> connectDB(){
    sql::Driver* driver = sql::mariadb::get_driver_instance();
    
    const std::string db_url = "jdbc:mariadb://localhost:3306/cw2";
    
    sql::Properties properties({
        {"user", "db_user"}, {"password", "malware"}});
    
    unique_ptr<sql::Connection> conn(driver->connect(db_url, properties));
    std::cerr << "connected to the database" << std::endl;
    return conn;
    
}


void displayUser(sql::Connection* conn){
    std::cout << "<div id='users'><h2>Users</h2>";
    std::cout << "<table><tr><th>User ID</th><th>Username</th><th>Email</th><th>Password</th><th>Is Admin</th></tr>";
    
    unique_ptr<sql::Statement> stmt(conn->createStatement());
    unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT ID, name, email, password, is_admin FROM users"));
    
    while (res->next()){
        std::cout<<"<tr>";
        std::cout<<"<td>"<<res->getInt("ID")<<"</td>";
        std::cout<<"<td>"<<res->getString("name")<<"</td>";
        std::cout<<"<td>"<<res->getString("email")<<"</td>";
        std::cout<<"<td>"<<res->getString("password")<<"</td>";
        std::cout<<"<td>"<<res->getInt("is_admin")<<"</td>";
        std::cout<<"</tr>";
    }
    
     std::cout<<"</table>";
}

void displayBlog(sql::Connection* conn){
    std::cout << "<div id='blog-posts'><h2>Blog Posts</h2>";
    std::cout << "<table><tr><th>Post Number</th><th>User ID</th><th>Title</th><th>Content</th><th>Created</th><th>Rating Id</th></tr>";
    
    unique_ptr<sql::Statement> stmt(conn->createStatement());
    unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT post_num, user_id, title, content, created, rating_id FROM blog_posts"));
    
    while (res->next()){
        std::cout<<"<tr>";
        std::cout<<"<td>"<<res->getInt("post_num")<<"</td>";
        std::cout<<"<td>"<<res->getInt("user_id")<<"</td>";
        std::cout<<"<td>"<<res->getString("title")<<"</td>";
        std::cout<<"<td>"<<res->getString("content")<<"</td>";
        std::cout<<"<td>"<<res->getString("created")<<"</td>";
        std::cout<<"<td>"<<res->getInt("rating_id")<<"</td>";
        std::cout<<"</tr>";
    }
    
     std::cout<<"</table>";
}

void displayRatings(sql::Connection* conn){
    std::cout << "<div id='ratings'><h2>Ratings</h2>";
    std::cout << "<table><tr><th>Rating ID</th><th>Post Number</th><th>Rating</th></tr>";
    
    unique_ptr<sql::Statement> stmt(conn->createStatement());
    unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT rating_id, post_num, rating FROM ratings"));
    
    while (res->next()){
        std::cout<<"<tr>";
        std::cout<<"<td>"<<res->getInt("rating_id")<<"</td>";
        std::cout<<"<td>"<<res->getInt("post_num")<<"</td>";
        std::cout<<"<td>"<<res->getString("rating")<<"</td>";
        std::cout<<"</tr>";
    }
    
     std::cout<<"</table>";
}


int main(){
    Cgicc cgi;
    std::cout<<HTTPHTMLHeader()<<std::endl;
    std::cout<<"<html><head><title>Database</title></head><body>"<<std::endl;
    
    std::cout << "<style>"
              "body { font-family: Times New Roman; background-color: #ffffff; color: #955151; margin: 10; padding: 20px; }"
              "table { width: 70%; border-collapse: collapse; margin-top: 10px; }"
              "th, td { padding: 10px; border: 1px solid #ddd; text-align: center; }"
              "th { background-color: #955151; color: #fff; }"
              "tr:nth-child(even) { background-color: #f9f9f9; }"
              "div { margin-bottom: 30px; }"
              "</style></head><body>";
    
    std::cout << "<header><h1>Database</h1></header>";
    
    unique_ptr<sql::Connection> conn = connectDB();
    if(conn){
        displayUser(conn.get());
        displayBlog(conn.get());
        displayRatings(conn.get());
    }else{
        std::cout<<"<p>Failed to connect to database.</p>" << std::endl;
    }
    
    std::cout<<"</body></html>"<<std::endl;
    return 0;
}
