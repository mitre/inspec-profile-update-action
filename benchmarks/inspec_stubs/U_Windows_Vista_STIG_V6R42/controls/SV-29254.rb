control 'SV-29254' do
  title 'Domain Controller authentication is not required to unlock the workstation.'
  desc 'This setting controls the behavior of the system when you attempt to unlock the workstation.  If this setting is enabled, the system will pass the credentials to the domain controller (if in a domain) for authentication before allowing the system to be unlocked.  This will be set to disabled per the FDCC.'
  desc 'check', 'Workstations - Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 

Navigate to Local Policies -> Security Options. 

If the value for “Interactive logon: Require domain controller authentication to unlock workstation” is not set to “Disabled”, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  ForceUnlockLogon

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Workstations - Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive logon: Require domain controller authentication to unlock workstation” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-18074r1_chk'
  tag severity: 'low'
  tag gid: 'V-3375'
  tag rid: 'SV-29254r1_rule'
  tag gtitle: 'Domain Controller authentication for unlock'
  tag fix_id: 'F-22888r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
