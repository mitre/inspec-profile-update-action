control 'SV-234391' do
  title 'The UEM server must be configured to invoke either host-OS functionality or server functionality to provide a trusted communication channel between itself and remote administrators that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:-IPsec,-SSH,-TLS, -HTTPS].'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network. 

Satisfies:FTP_TRP.1.1(1) Refinement'
  desc 'check', 'Verify the UEM server invokes either host-OS functionality or server functionality to provide a trusted communication channel between itself and remote administrators that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:
-IPsec,
-SSH,
-TLS, 
-HTTPS].

If the UEM server does not invoke either host-OS functionality or server functionality to provide a trusted communication channel between itself and remote administrators that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:
-IPsec,
-SSH,
-TLS, 
-HTTPS], this is a finding.'
  desc 'fix', 'Configure the UEM server to invoke either host-OS functionality or server functionality to provide a trusted communication channel between itself and remote administrators that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:
-IPsec,
-SSH,
-TLS, 
-HTTPS].'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37576r614183_chk'
  tag severity: 'medium'
  tag gid: 'V-234391'
  tag rid: 'SV-234391r617355_rule'
  tag stig_id: 'SRG-APP-000191-UEM-000118'
  tag gtitle: 'SRG-APP-000191'
  tag fix_id: 'F-37541r615961_fix'
  tag 'documentable'
  tag cci: ['CCI-001135']
  tag nist: ['SC-11 a']
end
