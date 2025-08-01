control 'SV-48077' do
  title 'Domain Controller authentication must not be required to unlock the workstation.'
  desc 'This setting controls the behavior of the system when there is an attempt to unlock the workstation.  If this setting is enabled, the system will pass the credentials to the domain controller (if in a domain) for authentication before allowing the system to be unlocked.  This may cause a denial of service if the workstation loses connectivity to the domain controller.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "Interactive logon: Require domain controller authentication to unlock workstation" is not set to "Disabled", this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: ForceUnlockLogon

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Require domain controller authentication to unlock workstation" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44816r1_chk'
  tag severity: 'low'
  tag gid: 'V-3375'
  tag rid: 'SV-48077r1_rule'
  tag stig_id: 'WN08-SO-000026'
  tag gtitle: 'Domain Controller authentication for unlock'
  tag fix_id: 'F-41215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
