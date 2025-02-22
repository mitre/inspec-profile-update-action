control 'SV-32446' do
  title 'NTLM will be prevented from falling back to a Null session.'
  desc 'This setting prevents NTLM from falling back to a Null (unauthenticated) session.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network Security: Allow LocalSystem NULL session fallback” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\System\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

Value Name:  allownullsessionfallback

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network Security: Allow LocalSystem NULL session fallback” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32912r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21952'
  tag rid: 'SV-32446r1_rule'
  tag gtitle: 'NTLM NULL Session Fallback'
  tag fix_id: 'F-28857r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
