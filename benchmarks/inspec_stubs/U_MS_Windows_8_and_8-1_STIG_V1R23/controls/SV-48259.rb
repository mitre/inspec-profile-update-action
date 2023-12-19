control 'SV-48259' do
  title 'Windows must elevate all applications in User Account Control, not just signed ones.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures whether Windows elevates all applications, not just signed ones.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "User Account Control: Only elevate executables that are signed and validated" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ValidateAdminCodeSignatures

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Only elevate executables that are signed and validated" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16008'
  tag rid: 'SV-48259r2_rule'
  tag stig_id: 'WN08-SO-000081'
  tag gtitle: 'UAC - Application Elevations'
  tag fix_id: 'F-41394r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
