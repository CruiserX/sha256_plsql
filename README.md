#### sha256_plsql
SHA256 PL/SQL Implementation for Oracle 10g,11g.
<br><br>
#### Installation
Compile package in sqlplus<br>

```
SQL> @sha256_pkg
Package created.
SQL> @sha256_body
Package body created.
```
#### Usage
```
SQL> select sha256.encrypt('test message') from dual;
3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728

SQL> select sha256.encrypt_raw('74657374206D657373616765') from dual;
3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728
```
