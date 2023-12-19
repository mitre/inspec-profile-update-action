control 'SV-222615' do
  title 'The application performing organization-defined security functions must verify correct operation of security functions.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed.

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to applications performing security functions and security function verification/testing.'
  desc 'check', 'Review the application documentation and interview the system administrator to determine if the application performs security function testing.

If the application is not designed or intended to perform security function testing, the requirement is not applicable.

Access the application design documents and determine if the application is designed to verify the correct operation of security functions.

Review application logs and take note of log entries that indicate security function testing is being performed and verified.

If the application is designed to perform security function testing and does not verify the correct operation of security functions, this is a finding.'
  desc 'fix', 'Design the application to verify the correct operation of security functions.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24285r493753_chk'
  tag severity: 'medium'
  tag gid: 'V-222615'
  tag rid: 'SV-222615r508029_rule'
  tag stig_id: 'APSC-DV-002760'
  tag gtitle: 'SRG-APP-000472'
  tag fix_id: 'F-24274r493754_fix'
  tag 'documentable'
  tag legacy: ['V-70283', 'SV-84905']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
