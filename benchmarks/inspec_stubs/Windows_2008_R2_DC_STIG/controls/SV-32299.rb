control 'SV-32299' do
  title 'The print driver installation privilege will be restricted to administrators.'
  desc 'Allowing users to install drivers can introduce malware or cause the instability of a system.  This capability should be restricted to the Administrators and Print Operators groups.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Devices: Prevent users from installing printer drivers” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers

Value Name:  AddPrinterDrivers

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Prevent users from installing printer drivers” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32722r1_chk'
  tag severity: 'low'
  tag gid: 'V-1151'
  tag rid: 'SV-32299r1_rule'
  tag gtitle: 'Secure Print Driver Installation'
  tag fix_id: 'F-83r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
