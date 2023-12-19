control 'SV-29451' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name:  DisableEnclosureDownload

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Turn off downloading of enclosures" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-57991r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15682'
  tag rid: 'SV-29451r2_rule'
  tag gtitle: 'RSS Attachment Downloads'
  tag fix_id: 'F-62317r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
