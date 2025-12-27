control 'SV-68891' do
  title 'The ALG must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application.

Network devices with the functionality to perform application layer inspection may be leveraged to validate data content of network communications. Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software typically follows well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If network elements use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Pre-screening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functionality."
  desc 'check', 'Verify the ALG checks the validity of all data inputs except those specifically identified by the organization.

If the ALG does not check the validity of all data inputs except those specifically identified by the organization, this is a finding.'
  desc 'fix', 'Configure the ALG to check the validity of all data inputs except those specifically identified by the organization.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54645'
  tag rid: 'SV-68891r1_rule'
  tag stig_id: 'SRG-NET-000401-ALG-000127'
  tag gtitle: 'SRG-NET-000401-ALG-000127'
  tag fix_id: 'F-59501r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
