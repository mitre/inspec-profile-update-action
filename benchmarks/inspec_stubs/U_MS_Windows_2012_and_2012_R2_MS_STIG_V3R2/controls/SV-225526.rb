control 'SV-225526' do
  title 'The print driver installation privilege must be restricted to administrators.'
  desc 'Allowing users to install drivers can introduce malware or cause the instability of a system.  Print driver installation should be restricted to administrators.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\

Value Name: AddPrinterDrivers

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Devices: Prevent users from installing printer drivers" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27225r471920_chk'
  tag severity: 'low'
  tag gid: 'V-225526'
  tag rid: 'SV-225526r569185_rule'
  tag stig_id: 'WN12-SO-000089'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27213r471921_fix'
  tag 'documentable'
  tag legacy: ['SV-52214', 'V-1151']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
