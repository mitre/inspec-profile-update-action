control 'SV-48337' do
  title 'The Windows SmartScreen must be configured to require approval from an administrator before running downloaded unknown software.'
  desc 'Windows SmartScreen helps protect systems from programs downloaded from the Internet that may be malicious. Requiring administrator approval before running unknown software will prevent users from executing potentially malicious programs.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnableSmartScreen

Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Configure Windows SmartScreen" to "Enabled" with "Require approval from an administrator before running downloaded unknown software" selected.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36707'
  tag rid: 'SV-48337r2_rule'
  tag stig_id: 'WN08-CC-000088'
  tag gtitle: 'WINCC-000088'
  tag fix_id: 'F-71689r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
