control 'SV-234379' do
  title 'When the UEM server cannot establish a connection to determine the validity of a certificate, the server must be configured not to have the option to accept the certificate.'
  desc 'When an UEM server accepts an unverified certificate, it may be trusting a malicious actor. For example, messages signed with an invalid certificate may contain links to malware, which could lead to the installation or distribution of that malware on DoD information systems, leading to compromise of DoD sensitive information and other attacks. 

Satisfies:FIA_X509_EXT.2.2 
Reference:PP-MDM-412003'
  desc 'check', 'Verify the UEM server does not automatically accept a certificate when it cannot establish a connection to determine the validity of a certificate.

If the UEM server automatically accepts a certificate when it cannot establish a connection to determine the validity of a certificate, this is a finding.'
  desc 'fix', 'Configure the UEM server to not automatically accept a certificate when it cannot establish a connection to determine the validity of a certificate.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37564r614147_chk'
  tag severity: 'medium'
  tag gid: 'V-234379'
  tag rid: 'SV-234379r879612_rule'
  tag stig_id: 'SRG-APP-000175-UEM-000106'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-37529r614148_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
