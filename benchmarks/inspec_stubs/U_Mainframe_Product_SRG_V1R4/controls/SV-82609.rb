control 'SV-82609' do
  title 'Mainframe Products requiring user access authentication must provide a logoff capability for a user-initiated communication session.'
  desc 'If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logoff messages as final messages prior to terminating sessions.'
  desc 'check', 'If the Mainframe Product has no logon capability, this requirement is not applicable.

If the Mainframe Product does not provide a logout capability for user initiated communication sessions, this is a finding.

Examine the Mainframe Product configuration settings to determine whether a user can logoff. If the configurations are not properly set, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product settings to provide capability of user-initiated logoff.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68119'
  tag rid: 'SV-82609r1_rule'
  tag stig_id: 'SRG-APP-000296-MFP-000007'
  tag gtitle: 'SRG-APP-000296-MFP-000007'
  tag fix_id: 'F-74235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
