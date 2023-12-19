control 'SV-225294' do
  title 'The system must be configured to audit Policy Change - Authentication Policy Change successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Authentication Policy Change records events related to changes in authentication policy, including Kerberos policy and Trust changes.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Policy Change -> Authentication Policy Change - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change -> "Audit Authentication Policy Change" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26993r471224_chk'
  tag severity: 'medium'
  tag gid: 'V-225294'
  tag rid: 'SV-225294r569185_rule'
  tag stig_id: 'WN12-AU-000087'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-26981r471225_fix'
  tag 'documentable'
  tag legacy: ['SV-52981', 'V-26548']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
