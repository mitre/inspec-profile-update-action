control 'SV-48200' do
  title 'User Account Control must switch to the secure desktop when prompting for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting ensures that the elevation prompt is only used in secure desktop mode.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "User Account Control: Switch to the secure desktop when prompting for elevation" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: PromptOnSecureDesktop

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Switch to the secure desktop when prompting for elevation" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14241'
  tag rid: 'SV-48200r2_rule'
  tag stig_id: 'WN08-SO-000084'
  tag gtitle: 'UAC - Secure Desktop Mode'
  tag fix_id: 'F-41336r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
