control 'SV-1165' do
  title 'The computer account password is prevented from being reset.'
  desc 'As a part of Windows security, computer account passwords are changed automatically.  Enabling this policy to disable automatic password changes can make the system more vulnerable to malicious access.  Frequent password changes can be a significant safeguard for your system.  If this policy is disabled, a new password for the computer account will be generated every week.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Domain Member: Disable Machine Account Password Changes” is not set to  “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name:  DisablePasswordChange

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Disable Machine Account Password Changes” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-116r1_chk'
  tag severity: 'low'
  tag gid: 'V-1165'
  tag rid: 'SV-1165r1_rule'
  tag gtitle: 'Computer Account Password Reset'
  tag fix_id: 'F-102r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
