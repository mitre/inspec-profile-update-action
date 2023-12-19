control 'SV-253311' do
  title 'The system must be configured to audit Detailed Tracking - PNP Activity successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Plug and Play activity records events related to the successful connection of external devices.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Detailed Tracking >> Plug and Play Events - Success'
  desc 'fix', 'Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Detailed Tracking >> "Audit PNP Activity" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56764r829015_chk'
  tag severity: 'medium'
  tag gid: 'V-253311'
  tag rid: 'SV-253311r829017_rule'
  tag stig_id: 'WN11-AU-000045'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-56714r829016_fix'
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1)']
end
