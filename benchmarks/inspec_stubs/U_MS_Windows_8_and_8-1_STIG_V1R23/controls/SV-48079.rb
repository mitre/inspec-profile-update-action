control 'SV-48079' do
  title 'The system must be configured to prevent anonymous users from having the same rights as the Everyone group.'
  desc 'Access by anonymous users must be restricted.  If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users must not have these permissions or rights.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for "Network access: Let everyone permissions apply to anonymous users" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Let everyone permissions apply to anonymous users" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44818r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3377'
  tag rid: 'SV-48079r1_rule'
  tag stig_id: 'WN08-SO-000054'
  tag gtitle: 'Everyone Anonymous rights'
  tag fix_id: 'F-41217r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1, ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
