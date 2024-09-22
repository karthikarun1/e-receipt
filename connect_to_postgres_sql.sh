# Uses $HOME/.pgpass to automatically connect using the supplied
# password and not prompt for the password
 psql -h localhost -p 5432 -U myuser -d mydb
