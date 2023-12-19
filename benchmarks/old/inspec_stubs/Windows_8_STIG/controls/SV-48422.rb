control 'SV-48422' do
  title 'NTLM must be prevented from falling back to a Null session.'
  desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Network Security: Allow LocalSystem NULL session fallback" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\System\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

Value Name: allownullsessionfallback

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network Security: Allow LocalSystem NULL session fallback" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45091r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21952'
  tag rid: 'SV-48422r2_rule'
  tag stig_id: 'WN08-SO-000062'
  tag gtitle: 'NTLM NULL Session Fallback'
  tag fix_id: 'F-41553r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
