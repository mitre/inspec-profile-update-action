control 'SV-48284' do
  title 'The system must be configured to audit Object Access - Removable Storage failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing object access for removable media records events related to access attempts on file system objects on removable storage devices.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding:

Object Access -> Removable Storage - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> "Audit Removable Storage" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44962r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36667'
  tag rid: 'SV-48284r2_rule'
  tag stig_id: 'WN08-AU-000016'
  tag gtitle: 'WINAU-000016'
  tag fix_id: 'F-41419r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECAR-2, ECAR-3'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
