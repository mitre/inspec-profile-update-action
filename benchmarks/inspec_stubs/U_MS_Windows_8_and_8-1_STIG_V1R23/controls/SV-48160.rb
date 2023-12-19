control 'SV-48160' do
  title 'Anonymous access to Named Pipes and Shares must be restricted.'
  desc 'Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access.  This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously",  both of which must be blank under other requirements.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Network access: Restrict anonymous access to Named Pipes and Shares" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: RestrictNullSessAccess

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44860r1_chk'
  tag severity: 'high'
  tag gid: 'V-6834'
  tag rid: 'SV-48160r2_rule'
  tag stig_id: 'WN08-SO-000058'
  tag gtitle: 'Anonymous Access to Named Pipes and Shares'
  tag fix_id: 'F-41298r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
