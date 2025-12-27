control 'SV-204831' do
  title 'Application servers must use NIST-approved or NSA-approved key management technology and processes.'
  desc 'An asymmetric encryption key must be protected during transmission. The public portion of an asymmetric key pair can be freely distributed without fear of compromise, and the private portion of the key must be protected. The application server will provide software libraries that applications can programmatically utilize to encrypt and decrypt information. These application server libraries must use NIST-approved or NSA-approved key management technology and processes when producing, controlling, or distributing symmetric and asymmetric keys.'
  desc 'check', 'Review application server configuration and the NIST FIPS certificate to validate the application server uses NIST-approved or NSA-approved key management technology and processes when producing, controlling or distributing symmetric and asymmetric keys.

If the application server does not use this NIST-approved or NSA-approved key management technology and processes, this is a finding.'
  desc 'fix', 'Configure the application server to utilize NIST-approved or NSA-approved key management technology when the application server produces, controls, and distributes symmetric and asymmetric cryptographic keys.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4951r283134_chk'
  tag severity: 'medium'
  tag gid: 'V-204831'
  tag rid: 'SV-204831r508029_rule'
  tag stig_id: 'SRG-APP-000514-AS-000136'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-4951r283135_fix'
  tag 'documentable'
  tag legacy: ['SV-71819', 'V-57543']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
