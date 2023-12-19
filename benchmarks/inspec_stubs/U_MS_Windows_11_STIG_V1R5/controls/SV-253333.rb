control 'SV-253333' do
  title 'The system must be configured to audit System - Security State Change successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security State Change records events related to changes in the security state, such as startup and shutdown of the system.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

System >> Security State Change - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System >> "Audit Security State Change" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56786r829081_chk'
  tag severity: 'medium'
  tag gid: 'V-253333'
  tag rid: 'SV-253333r829083_rule'
  tag stig_id: 'WN11-AU-000140'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-56736r829082_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
