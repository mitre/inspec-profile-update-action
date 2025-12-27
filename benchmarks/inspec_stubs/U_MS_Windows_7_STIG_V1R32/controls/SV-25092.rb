control 'SV-25092' do
  title 'The system is configured to give anonymous users Everyone rights.'
  desc 'This setting helps define the permissions that anonymous users have.  If this setting is enabled then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users should not have these permissions or rights.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for “Network access: Let everyone permissions apply to anonymous users” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  EveryoneIncludesAnonymous

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Let everyone permissions apply to anonymous users” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-32743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3377'
  tag rid: 'SV-25092r1_rule'
  tag gtitle: 'Everyone Anonymous rights'
  tag fix_id: 'F-133r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
