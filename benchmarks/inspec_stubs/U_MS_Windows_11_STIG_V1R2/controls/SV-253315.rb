control 'SV-253315' do
  title 'The system must be configured to audit Logon/Logoff - Logoff successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Logoff records user logoffs. If this is an interactive logoff, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings to override audit policy category settings" must be set to "Enabled" (WN11-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Logon/Logoff >> Logoff - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Logoff" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56768r829027_chk'
  tag severity: 'medium'
  tag gid: 'V-253315'
  tag rid: 'SV-253315r829029_rule'
  tag stig_id: 'WN11-AU-000065'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-56718r829028_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
