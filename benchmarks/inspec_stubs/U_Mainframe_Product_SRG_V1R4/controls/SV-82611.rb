control 'SV-82611' do
  title 'The Mainframe Product must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations, databases, and password-protected websites/web-based services. Logoff messages for web page access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, file transfer protocol (FTP) sessions, information systems typically send logoff messages as final messages prior to terminating sessions.'
  desc 'check', 'If the Mainframe Product has no logon capability, this requirement is not applicable.

Examine the Mainframe Product configuration settings to determine whether the Mainframe Product displays an explicit logoff message. If it does not, this is a finding'
  desc 'fix', 'Configure the Mainframe Product to display a specific logoff message.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68679r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68121'
  tag rid: 'SV-82611r1_rule'
  tag stig_id: 'SRG-APP-000297-MFP-000008'
  tag gtitle: 'SRG-APP-000297-MFP-000008'
  tag fix_id: 'F-74237r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
