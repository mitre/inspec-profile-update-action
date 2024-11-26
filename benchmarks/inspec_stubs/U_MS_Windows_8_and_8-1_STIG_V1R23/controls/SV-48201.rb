control 'SV-48201' do
  title 'User Account Control must virtualize file and registry write failures to per-user locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures non-UAC compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "User Account Control: Virtualize file and registry write failures to per-user locations" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44880r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14242'
  tag rid: 'SV-48201r2_rule'
  tag stig_id: 'WN08-SO-000085'
  tag gtitle: 'UAC - Non UAC Compliant Application Virtualization'
  tag fix_id: 'F-41337r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
