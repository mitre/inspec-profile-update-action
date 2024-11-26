control 'SV-204832' do
  title 'The application server must use DoD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc 'check', 'Review the application server configuration to determine if the application server utilizes approved PKI Class 3 or Class 4 certificates.

If the application server is not configured to use approved DoD or CNS certificates, this is a finding.'
  desc 'fix', 'Configure the application server to use DoD- or CNSS-approved Class 3 or Class 4 PKI certificates.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4952r283137_chk'
  tag severity: 'medium'
  tag gid: 'V-204832'
  tag rid: 'SV-204832r508029_rule'
  tag stig_id: 'SRG-APP-000514-AS-000137'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-4952r283138_fix'
  tag 'documentable'
  tag legacy: ['SV-71821', 'V-57545']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
