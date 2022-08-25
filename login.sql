use login;
create table users(
id int auto_increment primary key,
email varchar (80),
username varchar (100),
password_hash varchar (200)
);
select * from users;