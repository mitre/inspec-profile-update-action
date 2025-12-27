control 'SV-226205' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Prevent downloading of enclosures" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27907r475938_chk'
  tag severity: 'medium'
  tag gid: 'V-226205'
  tag rid: 'SV-226205r794504_rule'
  tag stig_id: 'WN12-CC-000105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27895r475939_fix'
  tag 'documentable'
  tag legacy: ['SV-53040', 'V-15682']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
