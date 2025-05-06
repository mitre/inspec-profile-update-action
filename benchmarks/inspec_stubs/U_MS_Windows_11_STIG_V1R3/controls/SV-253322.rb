control 'SV-253322' do
  title 'Windows 11 must be configured to audit Object Access - Other Object Access Events failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:

Open PowerShell or a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"
Compare the AuditPol settings with the following:
Object Access >> Other Object Access Events - Failure

If the system does not audit the above, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Other Object Access Events" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56775r829048_chk'
  tag severity: 'medium'
  tag gid: 'V-253322'
  tag rid: 'SV-253322r829050_rule'
  tag stig_id: 'WN11-AU-000084'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag fix_id: 'F-56725r829049_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
