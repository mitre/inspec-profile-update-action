control 'SV-225064' do
  title 'User Account Control must automatically deny standard user requests for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting controls the behavior of elevation when requested by a standard user account.

'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2016 versus Server with Desktop Experience) as well as Nano Server.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorUser

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26755r466094_chk'
  tag severity: 'medium'
  tag gid: 'V-225064'
  tag rid: 'SV-225064r852389_rule'
  tag stig_id: 'WN16-SO-000490'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-26743r466095_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00156']
  tag 'documentable'
  tag legacy: ['SV-88377', 'V-73713']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
