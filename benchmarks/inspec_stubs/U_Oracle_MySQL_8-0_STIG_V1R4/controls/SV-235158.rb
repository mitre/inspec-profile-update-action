control 'SV-235158' do
  title 'The MySQL Database Server 8.0 and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack.'
  desc %q(With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

The principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).

When dynamic execution is necessary, ways to mitigate the risk include the following, which should be implemented both in the on-screen application and at the database level, in the stored procedures:
-- Allow strings as input only when necessary. 
-- Rely on data typing to validate numbers, dates, etc. Do not accept invalid values. If substituting other values for them, think carefully about whether this could be subverted.
-- Limit the size of input strings to what is truly necessary.
-- If single quotes/apostrophes, double quotes, semicolons, equal signs, angle brackets, or square brackets will never be valid as input, reject them.
-- If comment markers will never be valid as input, reject them. In SQL, these are -- or /*  */ 
-- If HTML and XML tags, entities, comments, etc., will never be valid, reject them.
-- If wildcards are present, reject them unless truly necessary. In SQL these are the underscore and the percentage sign, and the word "ESCAPE" is also a clue that wildcards are in use.
-- If SQL key words, such as SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, ESCAPE, UNION, GRANT, REVOKE, DENY, MODIFY will never be valid, reject them. Use case-insensitive comparisons when    searching for these. Bear in mind that some of these words, particularly Grant (as a person's name), could also be valid input. 
-- If there are range limits on the values that may be entered, enforce those limits.
-- Institute procedures for inspection of programs for correct use of dynamic coding, by a party other than the developer.
-- Conduct rigorous testing of program modules that use dynamic coding, searching for ways to subvert the intended use.
-- Record the inspection and testing in the system documentation.
-- Bear in mind that all this applies not only to screen input, but also to the values in an incoming message to a web service or to a stored procedure called by a software component that has not itself been hardened in these ways. Not only can the caller be subject to such vulnerabilities; it may itself be the attacker.

The MySQL Firewall runs within the MySQL server and enables database administrators to permit or deny SQL statement execution based on matching against whitelists of accepted statement patterns. This hardens MySQL Server against attacks such as SQL injection or attempts to exploit applications by using them outside of their legitimate query workload characteristics.)
  desc 'check', "Review MySQL Database Server 8.0 source code (stored procedures, functions, and triggers) and application source code to identify cases of dynamic code execution.

Determine if the MySQL Enterprise Firewall is installed and trained to recognize normal behavior and block or alert of abnormal requests. Run the following command:
SHOW GLOBAL VARIABLES LIKE 'mysql_firewall_mode';

Review firewall users and Mode.
SELECT * FROM INFORMATION_SCHEMA.MYSQL_FIREWALL_USERS;
If no rows are returned and no firewall allow lists are active, this is a finding.

If LEARNING is returned, the firewall is building an allow list for the userhost user.

If PROTECTING is returned, the firewall will only permit SQL on the allow list for the userhost user to execute.

If DETECTING is returned, the firewall will write to the firewall log SQL not on the allow list for the userhost user to execute.
 
If dynamic code execution is employed without protective measures against code injection, this is a finding."
  desc 'fix', "Where dynamic code execution is used, modify the code to implement protections against code injection. 

Enable the MySQL Enterprise Firewall by running this script, which is located in the mysql home share sub directory.   
mysql -u root -p mysql < linux_install_firewall.sql

Train the firewall for users where dynamic code injection is possible, for examples applications that allow user input.

CALL mysql.sp_set_firewall_mode('fwuser@localhost', 'RECORDING');

Once the allowlist for the user/host has been captured, the firewall can be placed in PROTECTING (active blocking) or DETECTING(logging) mode.
CALL mysql.sp_set_firewall_mode('fwuser@localhost', 'PROTECTING');
CALL mysql.sp_set_firewall_mode('fwuser@localhost', 'DETECTING');"
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38377r623594_chk'
  tag severity: 'medium'
  tag gid: 'V-235158'
  tag rid: 'SV-235158r879652_rule'
  tag stig_id: 'MYS8-00-007500'
  tag gtitle: 'SRG-APP-000251-DB-000392'
  tag fix_id: 'F-38340r623595_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
