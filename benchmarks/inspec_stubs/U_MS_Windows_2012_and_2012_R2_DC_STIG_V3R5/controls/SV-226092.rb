control 'SV-226092' do
  title 'The system must be configured to audit Detailed Tracking - Process Creation successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Process Creation records events related to the creation of a process and the source.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Detailed Tracking -> Process Creation - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> "Audit Process Creation" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27794r475599_chk'
  tag severity: 'medium'
  tag gid: 'V-226092'
  tag rid: 'SV-226092r794343_rule'
  tag stig_id: 'WN12-AU-000023'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-27782r475600_fix'
  tag 'documentable'
  tag legacy: ['SV-52999', 'V-26539']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
