control 'SV-221923' do
  title 'The Central Log Server must provide a logout capability for user initiated communication session.'
  desc 'If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logout messages as final messages prior to terminating sessions.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server provides a logout capability for user initiated sessions.

If the Central Log Server does not provide a logout capability for user initiated sessions, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to provide a logout capability for user initiated sessions.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23638r420111_chk'
  tag severity: 'medium'
  tag gid: 'V-221923'
  tag rid: 'SV-221923r855320_rule'
  tag stig_id: 'SRG-APP-000296-AU-000560'
  tag gtitle: 'SRG-APP-000296'
  tag fix_id: 'F-23627r420112_fix'
  tag 'documentable'
  tag legacy: ['SV-109121', 'V-100017']
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
