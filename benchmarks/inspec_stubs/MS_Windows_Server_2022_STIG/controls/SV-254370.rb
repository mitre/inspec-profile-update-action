control 'SV-254370' do
  title 'Windows Server 2022 must prevent attachments from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> Prevent downloading of enclosures to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57855r848924_chk'
  tag severity: 'medium'
  tag gid: 'V-254370'
  tag rid: 'SV-254370r848926_rule'
  tag stig_id: 'WN22-CC-000390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57806r848925_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
