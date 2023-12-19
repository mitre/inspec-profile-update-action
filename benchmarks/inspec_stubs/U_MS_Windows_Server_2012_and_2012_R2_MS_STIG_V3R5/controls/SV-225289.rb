control 'SV-225289' do
  title 'The system must be configured to audit Object Access - Central Access Policy Staging failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Central Access Policy Staging auditing under Object Access is used to enable the recording of events related to differences in permissions between central access policies and proposed policies.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Object Access -> Central Policy Staging - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> "Audit Central Access Policy Staging" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26988r471209_chk'
  tag severity: 'medium'
  tag gid: 'V-225289'
  tag rid: 'SV-225289r569185_rule'
  tag stig_id: 'WN12-AU-000060'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-26976r471210_fix'
  tag 'documentable'
  tag legacy: ['SV-52159', 'V-40200']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
