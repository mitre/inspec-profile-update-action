control 'SV-48170' do
  title 'The system must be configured to hide the computer from the browse list.'
  desc 'Identifying the computer name on a network could provide an attacker with information useful in gaining access.  This setting prevents the computer name from displaying in the browse list.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \System\CurrentControlSet\Services\Lanmanserver\Parameters\

Value Name: Hidden

Value Type: REG_DWORD
Value: 1)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44870r1_chk'
  tag severity: 'low'
  tag gid: 'V-14231'
  tag rid: 'SV-48170r2_rule'
  tag stig_id: 'WN08-SO-000040'
  tag gtitle: 'Hide Computer'
  tag fix_id: 'F-41308r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
