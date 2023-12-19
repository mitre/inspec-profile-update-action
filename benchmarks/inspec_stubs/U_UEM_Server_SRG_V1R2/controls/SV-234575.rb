control 'SV-234575' do
  title 'The UEM server must be configured to use X.509v3 certificates for code signing for integrity verification.'
  desc 'It is critical that the UEM server validate code signing certificates for key activities such as code signing for system software updates, code signing for integrity verification, and policy signing. Otherwise, there is no assurance that a malicious actor has not inserted itself in the process of packaging the code or policy. For example, messages signed with an invalid certificate may contain links to malware, which could lead to the installation or distribution of that malware on DoD information systems, leading to compromise of DoD sensitive information and other attacks. Therefore, the MDM server must have the capability to enforce a policy for this control. 

Satisfies:FMT_SMF.1.1(2) c.8, FIA_X509_EXT.2.1 
Reference:PP-MDM-412002'
  desc 'check', 'Verify the UEM server uses X.509v3 certificates for code signing for integrity verification.

If the UEM server does not use X.509v3 certificates for code signing for integrity verification, this is a finding.'
  desc 'fix', 'Configure the UEM server to use X.509v3 certificates for code signing for integrity verification.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37760r615359_chk'
  tag severity: 'medium'
  tag gid: 'V-234575'
  tag rid: 'SV-234575r879798_rule'
  tag stig_id: 'SRG-APP-000427-UEM-000300'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-37725r615360_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
