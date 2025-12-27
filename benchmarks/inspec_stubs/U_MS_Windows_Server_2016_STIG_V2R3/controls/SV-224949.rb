control 'SV-224949' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> "Prevent downloading of enclosures" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26640r465749_chk'
  tag severity: 'medium'
  tag gid: 'V-224949'
  tag rid: 'SV-224949r569186_rule'
  tag stig_id: 'WN16-CC-000420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26628r465750_fix'
  tag 'documentable'
  tag legacy: ['SV-88241', 'V-73577']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
