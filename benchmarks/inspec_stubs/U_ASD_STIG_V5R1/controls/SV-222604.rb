control 'SV-222604' do
  title 'The application must protect from command injection.'
  desc 'A command injection attack is an attack on a vulnerable application where improperly validated input is passed to a command shell setup in the application. The result is the ability of an attacker to execute OS commands via the application.

A command injection allows an attacker to execute their own commands with the same privileges as the application executing.

The following is an example of a URL based command injection attack.

Before alteration:
http://sitename/cgi-bin/userData.pl?doc=user1.txt

Example URL modified: 
http://sitename/cgi-bin/userData.pl?doc=/bin/ls|

The result is the execution of the command “/bin/ls” which could allow the attacker to list contents of the directory via the browser.

The following is a list of functions vulnerable to command injection sorted according to language.  

Language Functions/Characters
- C/C++  - system(), popen(), execlp(), execvp(), ShellExecute(), ShellExecuteEx(), _wsystem()
- Perl - system, exec, `,open, |, eval, /e
- Python - exec, eval, os.system, os.popen, execfile, input, compile
- Java - Class.forName(), Class.newInstance(), Runtime.exec()'
  desc 'check', 'Review the application documentation and the system configuration settings.

Interview the application administrator for details regarding security assessment including automated code review and vulnerability scans conducted to test for command injection.

Review the scan results from the entire application.

Verify scan configuration is set to check for command injection vulnerabilities.

If results indicate vulnerability, verify a subsequent scan has been run to ensure the issue has been remediated.

Manual test procedures are available on the OWASP website. Procedures may need to be modified to suit application architecture.

https://www.owasp.org/index.php/Testing_for_Command_Injection_%28OTG-INPVAL-013%29

If testing results are not provided demonstrating the vulnerability does not exist, or if the application representative cannot demonstrate how actions are taken to identify and protect from command injection vulnerabilities, this is a finding.'
  desc 'fix', 'Modify the application so as to escape/sanitize special character input or configure the system to protect against command injection attacks based on application architecture.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24274r493720_chk'
  tag severity: 'high'
  tag gid: 'V-222604'
  tag rid: 'SV-222604r508029_rule'
  tag stig_id: 'APSC-DV-002510'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-24263r493721_fix'
  tag 'documentable'
  tag legacy: ['SV-84883', 'V-70261']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
