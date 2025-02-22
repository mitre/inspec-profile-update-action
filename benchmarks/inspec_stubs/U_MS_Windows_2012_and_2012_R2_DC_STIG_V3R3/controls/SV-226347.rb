control 'SV-226347' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28049r476885_chk'
  tag severity: 'medium'
  tag gid: 'V-226347'
  tag rid: 'SV-226347r794648_rule'
  tag stig_id: 'WN12-SO-000086'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-28037r476886_fix'
  tag 'documentable'
  tag legacy: ['SV-52223', 'V-15991']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
