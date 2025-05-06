control 'SV-88223' do
  title 'Windows Server 2016 Windows SmartScreen must be enabled.'
  desc 'Windows SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen will warn users of potentially malicious programs.'
  desc 'check', 'This is applicable to unclassified systems; for other systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnableSmartScreen

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Configure Windows SmartScreen" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-94161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73559'
  tag rid: 'SV-88223r2_rule'
  tag stig_id: 'WN16-CC-000330'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-80009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
