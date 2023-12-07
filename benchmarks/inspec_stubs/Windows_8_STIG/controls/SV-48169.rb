control 'SV-48169' do
  title 'Audit policy using subcategories must be enabled.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.  
This setting allows administrators to enable more precise auditing capabilities.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.  

If the value for "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: SCENoApplyLegacyAuditPolicy

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14230'
  tag rid: 'SV-48169r2_rule'
  tag stig_id: 'WN08-SO-000009'
  tag gtitle: 'Audit Policy Subcategory Setting'
  tag fix_id: 'F-41307r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
