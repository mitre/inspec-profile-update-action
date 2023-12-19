control 'SV-48051' do
  title 'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Interactive logon: Smart card removal behavior" is not set to "Lock Workstation" or "Force Logoff", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
 
Value Name:  SCRemoveOption

Value Type:  REG_SZ
Value:  1 (Lock Workstation) or 2 (Force Logoff)

This can be left not configured or set to "No action" on workstations with the following conditions.  This must be documented with the ISSO.
-The setting cannot be configured due to mission needs, or because it interferes with applications.
-Policy must be in place that users manually lock workstations when leaving them unattended.
-The screen saver is properly configured to lock as required.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive logon: Smart card removal behavior" to  "Lock Workstation" or "Force Logoff".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44790r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1157'
  tag rid: 'SV-48051r2_rule'
  tag stig_id: 'WN08-SO-000027'
  tag gtitle: 'Smart Card Removal Option'
  tag fix_id: 'F-41189r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
