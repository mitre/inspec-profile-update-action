control 'SV-32320' do
  title 'A system must be logged on to before removing from a docking station.'
  desc 'This setting controls the ability to undock the system without having to log on.  Since the removal of a computer should be controlled, users should have to log on before undocking the computer to ensure that they have the appropriate rights to undock the system.  In addition to software security settings, physical security should be in place to prevent unauthorized removal of computers.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Devices: Allow Undock Without Having to Log On” is not set to "Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

Value Name:  UndockWithoutLogon

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Allow Undock Without Having to Log On” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3372'
  tag rid: 'SV-32320r1_rule'
  tag gtitle: 'Undock Without Logging On'
  tag fix_id: 'F-130r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
