control 'SV-1157' do
  title 'The Smart Card removal option is set to take no action.'
  desc 'Determines what should happen when the smart card for a logged-on user is removed from the smart card reader.

The options are:
- No Action
- Lock Workstation
- Force Logoff'
  desc 'check', "Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 

Navigate to Local Policies -> Security Options. 

If the value for “Interactive logon: Smart card removal behavior” is not set to “Lock Workstation”, or “Force Logoff”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  SCRemoveOption

Value Type:  REG_SZ
Value:  1 (Lock Workstation) or 2 (Force Logoff)

Documentable Explanation:  This can be left not configured or set to “No action” on workstations with the following conditions.   This will be documented with the IAO.
•The setting can't be configured due to mission needs, interferes with applications.
•Policy must be in place that users manually lock workstations when leaving them unattended.
•Screen saver requirement is properly configured to lock as required in V0001122."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive logon: Smart card removal behavior” to  “Lock Workstation” or “Force Logoff”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-28790r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1157'
  tag rid: 'SV-1157r1_rule'
  tag gtitle: 'Smart Card Removal Option'
  tag fix_id: 'F-105r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
