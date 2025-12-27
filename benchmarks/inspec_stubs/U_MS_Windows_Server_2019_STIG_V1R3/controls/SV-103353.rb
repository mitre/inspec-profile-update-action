control 'SV-103353' do
  title 'Windows Server 2019 must prevent attachments from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> "Prevent downloading of enclosures" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93265'
  tag rid: 'SV-103353r1_rule'
  tag stig_id: 'WN19-CC-000390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-99511r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
