control 'SV-234390' do
  title 'The UEM server must be configured to provide a trusted communication channel between itself and authorized IT entities using [selection:
-IPsec,
-SSH,
-mutually authenticated TLS, 
-mutually authenticated DTLS, 
-HTTPS].'
  desc 'Examples of authorized IT entities: audit server, Active Directory, software update server, and database server.

Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network. 

Satisfies:FTP_ITC.1.1(1) Refinement 
Reference:PP-MDM-412062'
  desc 'check', 'Verify the UEM server provides a trusted communication channel between itself and authorized IT entities using [selection:
-IPsec,
-SSH,
-mutually authenticated TLS, 
-mutually authenticated DTLS, 
-HTTPS].

If the UEM server does not provide a trusted communication channel between itself and authorized IT entities using [selection:
-IPsec,
-SSH,
-mutually authenticated TLS, 
-mutually authenticated DTLS, 
-HTTPS], this is a finding.'
  desc 'fix', 'Configure the UEM server to provide a trusted communication channel between itself and authorized IT entities using [selection:
-IPsec,
-SSH,
-mutually authenticated TLS, 
-mutually authenticated DTLS, 
-HTTPS].'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37575r614180_chk'
  tag severity: 'medium'
  tag gid: 'V-234390'
  tag rid: 'SV-234390r617355_rule'
  tag stig_id: 'SRG-APP-000191-UEM-000117'
  tag gtitle: 'SRG-APP-000191'
  tag fix_id: 'F-37540r614181_fix'
  tag 'documentable'
  tag cci: ['CCI-001135']
  tag nist: ['SC-11 a']
end
