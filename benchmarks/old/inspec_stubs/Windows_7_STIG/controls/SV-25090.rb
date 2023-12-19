control 'SV-25090' do
  title 'Anonymous enumeration of shares must be restricted.'
  desc 'Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Network access: Do not allow anonymous enumeration of SAM accounts and shares" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name:   RestrictAnonymous

Value Type:   REG_DWORD
Value:   1'
  desc 'fix', 'Configure the policy values for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62053r2_chk'
  tag severity: 'high'
  tag gid: 'V-1093'
  tag rid: 'SV-25090r2_rule'
  tag gtitle: 'Anonymous shares are not restricted'
  tag fix_id: 'F-66951r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
