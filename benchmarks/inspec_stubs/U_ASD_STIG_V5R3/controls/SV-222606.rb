control 'SV-222606' do
  title 'The application must validate all input.'
  desc 'Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software applications typically follow well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. 

Structured messages can contain raw or unstructured data interspersed with metadata or control information. If software applications use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. 

Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Prescreening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks.

Absence of input validation opens an application to improper manipulation of data. The lack of input validation can lead immediate access of application, denial of service, and corruption of data.

Invalid input includes presence of scripting tags within text fields, query string manipulation, and invalid data types and sizes.

When an application validates input, it will only execute provided input after it has evaluated the input, validated the input and determined the data is in an expected format, and content is not extraneous or malformed.

Comprehensive application security testing and code reviews are required to ensure the application is not vulnerable to input validation vulnerabilities.

Application security code reviews should be conducted during the development phase to find and address input validation errors. When code reviews are not possible, fuzz testing can be performed on the application to attempt and identify vulnerable data input fields.'
  desc 'check', 'Review the application documentation, the code review reports and the vulnerability assessment scan results from automated vulnerability assessment tools.

Verify scan configuration settings include input validation and fuzzing tests.

Test data entry fields on all pages/screens of the application.

Procedures on testing input are relevant to the architecture of the application.

A reference on input validation testing is included at the OWASP website. The site includes testing procedures for input validation that affect many different technologies.

Identify the relevant testing procedures based upon the application architecture and components being tested.

https://www.owasp.org/index.php/Testing_for_Input_Validation

If test results include input validation errors, or if no test results exist, this is a finding.'
  desc 'fix', 'Design and configure the application to validate input prior to executing commands.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24276r493726_chk'
  tag severity: 'medium'
  tag gid: 'V-222606'
  tag rid: 'SV-222606r879652_rule'
  tag stig_id: 'APSC-DV-002530'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-24265r493727_fix'
  tag 'documentable'
  tag legacy: ['SV-84887', 'V-70265']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
