control 'SV-25035' do
  title 'Print driver installation privilege must be restricted to administrators.'
  desc 'The print spooler allows users to add and to delete printer drivers on the local system.  This capability must be restricted to privileged groups to ensure only stable, non-malicious drivers are used.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Devices: Prevent users from installing printer drivers" is not set to  "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\

Value Name:  AddPrinterDrivers

Value Type:  REG_DWORD
Value:  1

If site circumstances require that users be able to install print drivers for locally attached printers, this exception must be documented with the ISSO.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Devices: Prevent users from installing printer drivers" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62061r1_chk'
  tag severity: 'low'
  tag gid: 'V-1151'
  tag rid: 'SV-25035r2_rule'
  tag gtitle: 'Secure Print Driver Installation'
  tag fix_id: 'F-66959r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
