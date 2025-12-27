control 'SV-109123' do
  title 'The Central Log Server must display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. Logout messages for web page access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logout messages as final messages prior to terminating sessions.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to display an explicit logout message to users indicating the reliable termination of authenticated sessions.

If the Central Log Server is not configured to display an explicit logout message to users, it is a finding.'
  desc 'fix', 'Configure the Central Log Server to display an explicit logout message to users indicating the reliable termination of authenticated sessions.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98869r1_chk'
  tag severity: 'low'
  tag gid: 'V-100019'
  tag rid: 'SV-109123r1_rule'
  tag stig_id: 'SRG-APP-000297-AU-000570'
  tag gtitle: 'SRG-APP-000297-AU-000570'
  tag fix_id: 'F-105703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
