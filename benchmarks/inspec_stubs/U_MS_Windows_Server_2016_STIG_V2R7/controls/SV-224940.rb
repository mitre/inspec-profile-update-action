control 'SV-224940' do
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
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26631r465722_chk'
  tag severity: 'medium'
  tag gid: 'V-224940'
  tag rid: 'SV-224940r569186_rule'
  tag stig_id: 'WN16-CC-000330'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26619r465723_fix'
  tag 'documentable'
  tag legacy: ['V-73559', 'SV-88223']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
