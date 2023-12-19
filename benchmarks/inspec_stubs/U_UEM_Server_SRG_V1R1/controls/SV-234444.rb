control 'SV-234444' do
  title 'The UEM server must display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. Logout messages for web page access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logout messages as final messages prior to terminating sessions.'
  desc 'check', 'Verify the UEM server displays an explicit logout message to users indicating the reliable termination of authenticated communications sessions.

If the UEM server does not display an explicit logout message to users indicating the reliable termination of authenticated communications sessions, this is a finding.'
  desc 'fix', 'Configure the UEM server to display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37629r614342_chk'
  tag severity: 'medium'
  tag gid: 'V-234444'
  tag rid: 'SV-234444r617355_rule'
  tag stig_id: 'SRG-APP-000297-UEM-000171'
  tag gtitle: 'SRG-APP-000297'
  tag fix_id: 'F-37594r614343_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
