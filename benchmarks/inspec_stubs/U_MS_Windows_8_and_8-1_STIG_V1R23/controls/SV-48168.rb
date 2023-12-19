control 'SV-48168' do
  title 'Auditing of Backup and Restore Privileges must be turned off.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.  
This setting prevents the system from generating audit events for every file backed up or restored which could fill the security log in Windows, making it difficult to identify actual issues.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.  

If the value for "Audit: Audit the use of Backup and Restore privilege" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa

Value Name: FullPrivilegeAuditing

Value Type: REG_BINARY
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Audit the use of Backup and Restore privilege" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44868r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14229'
  tag rid: 'SV-48168r1_rule'
  tag stig_id: 'WN08-SO-000008'
  tag gtitle: 'Audit Backup and Restore Privileges'
  tag fix_id: 'F-41306r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
