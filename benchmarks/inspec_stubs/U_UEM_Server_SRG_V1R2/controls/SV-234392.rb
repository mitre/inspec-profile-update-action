control 'SV-234392' do
  title 'The UEM server must be configured to invoke either host-OS functionality or server functionality to provide a trusted communication channel between itself and managed devices that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:-TLS, -HTTPS].'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network. 

Satisfies:FTP_TRP.1.1(2) Refinement'
  desc 'check', 'Verify the UEM server invokes either host-OS functionality or server functionality to provide a trusted communication channel between itself and managed devices that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:
-TLS, 
-HTTPS].

If the UEM server does not invoke either host-OS functionality or server functionality to provide a trusted communication channel between itself and managed devices that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:
-TLS, 
-HTTPS], this is a finding.'
  desc 'fix', 'Configure the UEM server to invoke either host-OS functionality or server functionality to provide a trusted communication channel between itself and managed devices that provides assured identification of its endpoints and protection of the communicated data from modification and disclosure using [selection:
-TLS, 
-HTTPS].'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37577r614186_chk'
  tag severity: 'medium'
  tag gid: 'V-234392'
  tag rid: 'SV-234392r879623_rule'
  tag stig_id: 'SRG-APP-000191-UEM-000119'
  tag gtitle: 'SRG-APP-000191'
  tag fix_id: 'F-37542r615963_fix'
  tag 'documentable'
  tag cci: ['CCI-001135']
  tag nist: ['SC-11 a']
end
