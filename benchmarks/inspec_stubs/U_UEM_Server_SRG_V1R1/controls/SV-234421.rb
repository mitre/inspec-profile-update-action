control 'SV-234421' do
  title 'The UEM server must check the validity of all data inputs.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application. 

Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software applications typically follow well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If software applications use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Prescreening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks."
  desc 'check', 'Verify the UEM server checks the validity of all data inputs.

If the UEM server does not check the validity of all data inputs, this is a finding.'
  desc 'fix', 'Configure the UEM server to check the validity of all data inputs.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37606r617398_chk'
  tag severity: 'medium'
  tag gid: 'V-234421'
  tag rid: 'SV-234421r617398_rule'
  tag stig_id: 'SRG-APP-000251-UEM-000148'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-37571r614274_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
