### Folder Structure & Attack Vectors

#### 1. `php-variants/`

Designed to bypass blacklists that only block the `.php` extension.

* **Extensions**: `.php3`, `.php4`, `.php5`, `.phtml`, `.phar`.
* **Obfuscation**: `.PHP` (case sensitivity), `.php.jpg` (double extension), and `.php%00.jpg` (null byte injection).

#### 2. `mime-bypass/`

Files for bypassing Content-Type or Magic Byte validation.

* **webshell_with_magic.php**: A PHP shell starting with image magic bytes (e.g., `GIF89a;`).
* **polyglot.php.jpg**: A valid image file containing embedded PHP code.

#### 3. `config/`

Targeting server configuration vulnerabilities to change how the server handles files.

* **.htaccess / .user.ini**: For Apache/PHP servers to override folder permissions or execute arbitrary code.
* **web.config**: For IIS (ASP.NET) servers to modify application settings.

#### 4. `docs-and-xss/`

Testing for client-side execution and secondary vulnerabilities.

* **SVG/HTML/XML**: Testing for **Stored XSS** via file upload.
* **PDF/Macro**: Testing for malicious document handling and macro execution.

#### 5. `other-backends/`

Webshells tailored for non-PHP environments:

* **ASP/ASPX**: IIS / Windows servers.
* **JSP/JSPX**: Java-based servers (Tomcat, JBoss).
* **CGI/PL**: Common Gateway Interface and Perl scripts.
* **SHTML**: Server-Side Includes (SSI) injection.

#### 6. `archives/`

Testing for **Zip Slip** or decompression vulnerabilities.

* Includes `.zip` and `.tar.gz` files to test if the server insecurely unpacks uploaded archives.

---

### Quick Usage

1. **Identify the Backend**: Determine if the server runs on PHP, ASP.NET, or Java.
2. **Test Extensions**: Start with `php-variants/` or `other-backends/` to see if executable scripts are allowed.
3. **Bypass Filters**: If direct uploads fail, try `mime-bypass/` to trick the MIME-type validation.
4. **Escalate**: Use `config/` files to force the server to execute your "image" as a script.

---

### ⚠️ Security Warning

These files are for **educational and authorized security testing only**. Never upload these to a system you do not own or have explicit permission to test.