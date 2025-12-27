control 'SV-25043' do
  title 'The system is not configured to require a strong session key.'
  desc 'This setting controls the requirement that strong session keys be used between systems.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Domain Member: Require Strong (Windows 2000 or Later) Session Key” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name:  RequireStrongKey

Value Type:  REG_DWORD
Value:  1
 
Warning: This setting may prevent a system from being joined to a domain if not configured consistently between systems.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Require Strong (Windows 2000 or Later) Session Key” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-502r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3374'
  tag rid: 'SV-25043r1_rule'
  tag gtitle: 'Strong Session Key'
  tag fix_id: 'F-5801r1_fix'
  tag 'documentable'
  tag potential_impacts: 'This setting may prevent a system from being joined to a domain if not configured consistently between systems.'
  tag third_party_tools: 'HK'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
