control 'SV-226105' do
  title 'The system must be configured to audit Object Access - Removable Storage successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Removable Storage auditing under Object Access records events related to access attempts on file system objects on removable storage devices.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Object Access >> Removable Storage - Success

Virtual machines or systems that use network attached storage may generate excessive audit events for secondary virtual drives or the network attached storage when this setting is enabled.  This may be set to Not Configured in such cases and would not be a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Removable Storage" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27807r475638_chk'
  tag severity: 'medium'
  tag gid: 'V-226105'
  tag rid: 'SV-226105r794364_rule'
  tag stig_id: 'WN12-AU-000081'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-27795r475639_fix'
  tag 'documentable'
  tag legacy: ['SV-51601', 'V-36668']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
