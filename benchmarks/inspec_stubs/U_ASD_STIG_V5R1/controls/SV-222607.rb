control 'SV-222607' do
  title 'The application must not be vulnerable to SQL Injection.'
  desc 'SQL Injection is a code injection attack against database applications. Malicious SQL statements are inserted into an application data entry field where they are submitted to the database and executed. This is a direct result of not validating input that is used by the application to perform a command or execute an action.

Successful attacks can read data, write data, execute administrative functions within the database, shutdown the DBMS, and in some cases execute OS commands.

Best practices to reduce the potential for SQL Injection vulnerabilities include:

Not using concatenation or replacement to build SQL queries.

Using prepared statements with parameterized queries that have been tested and validated not to be vulnerable to SQL Injection.

Using stored procedures that have been tested and validated not to be vulnerable to SQL Injection.

Escaping all user supplied input.

Additional steps to prevent SQL Injection can be found at the OWASP website:

https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet'
  desc 'check', 'Review the application documentation and interview the application administrator.

Request the latest vulnerability scan test results.

Verify the scan configuration is configured to test for SQL injection flaws.

Review the scan results to determine if any SQL injection flaws were detected during application testing.

If SQL injection flaws were discovered, request a subsequent scan that will show that the issues have been remediated.

If the scan results are not available, identify the database product in use and refer to the OWASP web application testing guide for detailed instructions on performing a manual SQL injection test. The instructions are located here and many tests are organized by database product:

https://www.owasp.org/index.php/Testing_for_SQL_Injection_%28OTG-INPVAL-005%29

If the application is vulnerable to SQL injection attack, contains SQL injection flaws, or if scan results do not exist, this is a finding.'
  desc 'fix', 'Modify the application and remove SQL injection vulnerabilities.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24277r493729_chk'
  tag severity: 'high'
  tag gid: 'V-222607'
  tag rid: 'SV-222607r508029_rule'
  tag stig_id: 'APSC-DV-002540'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-24266r493730_fix'
  tag 'documentable'
  tag legacy: ['SV-84889', 'V-70267']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
