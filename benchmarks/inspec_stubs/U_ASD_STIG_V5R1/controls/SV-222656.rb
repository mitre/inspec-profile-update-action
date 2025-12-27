control 'SV-222656' do
  title 'The application must not be subject to error handling vulnerabilities.'
  desc 'Error handling is the failure to check the return values of functions or catch top level exceptions within a program. Improper error handling in an application can lead to an application failure or possibly result in the application entering an insecure state. 

The primary way to detect error handling vulnerabilities is to perform code reviews. If a manual code review cannot be performed, static code analysis tools should be employed in conjunction with tests to help force the error conditions by specifying invalid input (such as fuzzed data and malformed filenames) and by using different accounts to run the application. These tests may give indications of vulnerability, but they are not comprehensive.

In order to minimize error handling errors, ensure proper return code and exception handling is implemented throughout the application.'
  desc 'check', 'Review the application documentation, code review reports and the results from static code analysis tools.

Identify the most recent security scans and code analysis testing conducted.  Verify testing configuration includes tests for error handling issues.

Check test results for identified error handling vulnerabilities within the application.

If the test results indicate the existence of error handling vulnerabilities and no remediation evidence is presented, this is a finding.

If no test results are available for review, this is a finding.'
  desc 'fix', 'Ensure proper return code and exception handling is implemented throughout the application.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24326r493876_chk'
  tag severity: 'medium'
  tag gid: 'V-222656'
  tag rid: 'SV-222656r508029_rule'
  tag stig_id: 'APSC-DV-003235'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24315r493877_fix'
  tag 'documentable'
  tag legacy: ['SV-85013', 'V-70391']
  tag cci: ['CCI-000366', 'CCI-003272']
  tag nist: ['CM-6 b', 'SA-15 (5)']
end
