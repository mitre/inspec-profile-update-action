control 'SV-48076' do
  title 'The system must be configured to require a strong session key.'
  desc 'A computer connecting to a domain controller will establish a secure channel.  Requiring strong session keys enforces 128-bit encryption between systems.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Domain Member: Require Strong (Windows 2000 or Later) Session Key" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 1
 
Warning: This setting may prevent a system from being joined to a domain if not configured consistently between systems.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain Member: Require Strong (Windows 2000 or Later) Session Key" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44815r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3374'
  tag rid: 'SV-48076r1_rule'
  tag stig_id: 'WN08-SO-000017'
  tag gtitle: 'Strong Session Key'
  tag fix_id: 'F-41214r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
