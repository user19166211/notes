g++ main.cpp -o main.cgi functions.cpp -lcgicc -lmariadbcpp -I/usr/include -L/usr/lib -lcrypto -lssl
sudo cp main.cgi /usr/lib/cgi-bin/
sudo chown www-data /usr/lib/cgi-bin/main.cgi
