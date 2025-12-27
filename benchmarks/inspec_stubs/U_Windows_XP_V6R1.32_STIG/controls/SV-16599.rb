control 'SV-16599' do
  title 'RSS Attachment Downloads'
  desc 'This check verifies that attachments are prevented from being downloaded from RSS feeds.'
  desc 'check', 'Note:  For Windows XP, this check only applies if Internet Explorer 7 or later is installed.

If the following registry value doesn’t exist or is not configured as specified this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name:	DisableEnclosureDownload

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Note:  For Windows XP, this only applies if Internet Explorer 7 or later is installed.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds “Turn off downloading of enclosures” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-15326r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15682'
  tag rid: 'SV-16599r1_rule'
  tag gtitle: 'RSS Attachment Downloads'
  tag fix_id: 'F-15549r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
