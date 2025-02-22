control 'SV-48229' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Prevent downloading of enclosures" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44908r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15682'
  tag rid: 'SV-48229r1_rule'
  tag stig_id: 'WN08-CC-000105'
  tag gtitle: 'RSS Attachment Downloads'
  tag fix_id: 'F-41365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
