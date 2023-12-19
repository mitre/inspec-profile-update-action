control 'SV-35983' do
  title 'The system will be configured to audit "Detailed Tracking -> Process Creation" successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred as well as detecting attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Process creation records events related to the creation of a process and the source.'
  desc 'check', 'Security Option “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings” must be set to “Enabled” (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges (“Run as Administrator”).
-Enter “AuditPol /get /category:*”.

Compare the Auditpol settings with the following.  If the system does not audit the following, this is a finding:

Detailed Tracking -> Process Creation  - Success'
  desc 'fix', 'Detailed auditing subcategories are configured in Security Settings -> Advanced Audit Policy Configuration.   The summary level settings under Security Settings -> Local Policies -> Audit Policy will not be enforced (see V-14230).

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> "Audit Process Creation" with “Success” selected.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-34098r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26539'
  tag rid: 'SV-35983r1_rule'
  tag stig_id: 'WINAU-000302'
  tag gtitle: 'Audit - Process Creation - Success'
  tag fix_id: 'F-29777r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
