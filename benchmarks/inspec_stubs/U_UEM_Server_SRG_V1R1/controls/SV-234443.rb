control 'SV-234443' do
  title 'The UEM server must provide logout capability for user-initiated communication sessions.'
  desc 'If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logout messages as final messages prior to terminating sessions. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431015'
  desc 'check', 'Verify the UEM server provides a logout capability for user-initiated communication sessions.

If the UEM server does not provide a logout capability for user-initiated communication sessions, this is a finding.'
  desc 'fix', 'Configure the UEM server to provide a logout capability for user-initiated communication sessions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37628r614339_chk'
  tag severity: 'medium'
  tag gid: 'V-234443'
  tag rid: 'SV-234443r617355_rule'
  tag stig_id: 'SRG-APP-000296-UEM-000170'
  tag gtitle: 'SRG-APP-000296'
  tag fix_id: 'F-37593r614340_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
