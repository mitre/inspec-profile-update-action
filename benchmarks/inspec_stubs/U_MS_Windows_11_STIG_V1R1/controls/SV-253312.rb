control 'SV-253312' do
  title 'The system must be configured to audit Detailed Tracking - Process Creation successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Process creation records events related to the creation of a process and the source.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Detailed Tracking >> Process Creation - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Detailed Tracking >> "Audit Process Creation" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56765r829018_chk'
  tag severity: 'medium'
  tag gid: 'V-253312'
  tag rid: 'SV-253312r829020_rule'
  tag stig_id: 'WN11-AU-000050'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-56715r829019_fix'
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-001784']
  tag nist: ['AU-12 c', 'CM-8 (3) (b)']
end
