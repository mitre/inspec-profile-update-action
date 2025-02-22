control 'SV-48057' do
  title 'The computer account password must not be prevented from being reset.'
  desc 'Computer account passwords are changed automatically on a regular basis.  Disabling automatic password changes can make the system more vulnerable to malicious access.  Frequent password changes can be a significant safeguard for your system.  A new password for the computer account will be generated every 30 days.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Domain Member: Disable Machine Account Password Changes" is not set to  "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: DisablePasswordChange

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain Member: Disable Machine Account Password Changes" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44796r1_chk'
  tag severity: 'low'
  tag gid: 'V-1165'
  tag rid: 'SV-48057r1_rule'
  tag stig_id: 'WN08-SO-000015'
  tag gtitle: 'Computer Account Password Reset'
  tag fix_id: 'F-41195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
