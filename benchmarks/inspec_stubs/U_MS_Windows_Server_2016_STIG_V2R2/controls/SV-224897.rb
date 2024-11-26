control 'SV-224897' do
  title 'Windows 2016 must be configured to audit Object Access - Other Object Access Events failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN16-SO-000050) for the detailed auditing subcategories to be effective.

Use the "AuditPol" tool to review the current Audit Policy configuration:

Open "PowerShell" or a "Command Prompt" with elevated privileges ("Run as Administrator").

Enter "AuditPol /get /category:*"

Compare the "AuditPol" settings with the following:

If the system does not audit the following, this is a finding.

Object Access >> Other Object Access Events - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Other Object Access Events" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26588r465593_chk'
  tag severity: 'medium'
  tag gid: 'V-224897'
  tag rid: 'SV-224897r569186_rule'
  tag stig_id: 'WN16-AU-000286'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-26576r465594_fix'
  tag 'documentable'
  tag legacy: ['SV-101011', 'V-90361']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
