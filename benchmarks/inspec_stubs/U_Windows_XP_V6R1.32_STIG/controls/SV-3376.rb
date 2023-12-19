control 'SV-3376' do
  title 'The system is configured to permit storage of credentials or .NET Passports.'
  desc 'This setting controls the storage of authentication credentials or .NET passports on the local system.  Such credentials should never be stored on the local machine as that may lead to account compromise.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network access: Do not allow storage of credentials or .NET passports for network authentication” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  DisableDomainCreds

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Do not allow storage of credentials or .NET passports for network authentication” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-171r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3376'
  tag rid: 'SV-3376r1_rule'
  tag gtitle: 'Storage of Passwords and Credentials'
  tag fix_id: 'F-132r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
