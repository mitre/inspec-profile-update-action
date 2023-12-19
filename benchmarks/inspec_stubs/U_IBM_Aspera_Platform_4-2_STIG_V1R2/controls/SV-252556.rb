control 'SV-252556' do
  title 'The IBM Aspera Platform must be configured to support centralized management and configuration.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

Network components requiring centralized audit log management must have the capability to support centralized management.

The DoD requires centralized management of all network component audit record content.

This requirement does not apply to audit logs generated on behalf of the device itself (management).

Support of centralized management of the IBM Aspera Platform is accomplished via use of IBM Aspera Console.'
  desc 'check', 'Verify the IBM Aspera Platform is configured to support centralized management and configuration. 

Navigate to the IBM Aspera Console webpage, login with an administrator account, and review the Nodes tab.

If all nodes managed by the organization are not listed, this is a finding.

If the IBM Aspera Platform implementation does not include IBM Aspera Console, this is a finding.'
  desc 'fix', 'Configure the IBM Aspera Platform to support centralized management and configuration.

Ensure the IBM Aspera Console server is installed and configured to manage all nodes within the organization.

Navigate to the IBM Aspera Console webpage, log in with an administrator account, and select the "Nodes" tab.

Select "New Managed Node" to add nodes to the IBM Aspera Console.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56012r817836_chk'
  tag severity: 'medium'
  tag gid: 'V-252556'
  tag rid: 'SV-252556r831490_rule'
  tag stig_id: 'ASP4-00-010100'
  tag gtitle: 'SRG-NET-000333-ALG-000049'
  tag fix_id: 'F-55962r817837_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
