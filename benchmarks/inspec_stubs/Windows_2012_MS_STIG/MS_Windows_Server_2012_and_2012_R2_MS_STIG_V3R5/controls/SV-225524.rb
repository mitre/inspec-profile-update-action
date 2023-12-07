control 'SV-225524' do
  title 'UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts.'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableUIADesktopToggle

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27223r471914_chk'
  tag severity: 'medium'
  tag gid: 'V-225524'
  tag rid: 'SV-225524r569185_rule'
  tag stig_id: 'WN12-SO-000086'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27211r471915_fix'
  tag 'documentable'
  tag legacy: ['V-15991', 'SV-52223']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
