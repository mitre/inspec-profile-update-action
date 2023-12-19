control 'SV-33620' do
  title 'Windows Server 2008 R2 domain controllers must be configured to audit Account Management - Computer Account Management successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred as well as detecting attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Computer Account Management records events such as the  creating, changing, deleting, renaming, disabling, or enabling computer accounts.'
  desc 'check', 'Security Option “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings” must be set to “Enabled” (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges (“Run as Administrator”).
-Enter “AuditPol /get /category:*”.

Compare the Auditpol settings with the following.  If the system does not audit the following, this is a finding:

Account Management >> Computer Account Management  - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management >> "Audit Computer Account Management" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-34083r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26531'
  tag rid: 'SV-33620r2_rule'
  tag stig_id: 'WINAU-000202-DC'
  tag gtitle: 'Audit - Computer Account Management - Success'
  tag fix_id: 'F-29760r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
