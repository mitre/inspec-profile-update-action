control 'SV-16934' do
  title 'UAC - Allow UIAccess applications to prompt for elevation without using the secure desktop'
  desc 'This check verifies whether User Interface Accessibility programs can automatically disable the secure desktop for elevation prompts for a standard user.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  EnableUIADesktopToggle

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15991'
  tag rid: 'SV-16934r1_rule'
  tag gtitle: 'UAC - UIAccess Secure Desktop'
  tag fix_id: 'F-28854r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
