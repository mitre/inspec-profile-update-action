control 'SV-48078' do
  title 'The system must be configured to prevent the storage of passwords and credentials.'
  desc 'This setting controls the storage of passwords and credentials for network authentication on the local system.  Such credentials must not be stored on the local machine as that may lead to account compromise.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for "Network access: Do not allow storage of passwords and credentials for network authentication" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: DisableDomainCreds

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow storage of passwords and credentials for network authentication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3376'
  tag rid: 'SV-48078r1_rule'
  tag stig_id: 'WN08-SO-000053'
  tag gtitle: 'Storage of Passwords and Credentials'
  tag fix_id: 'F-41216r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
