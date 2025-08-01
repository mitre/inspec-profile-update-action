control 'SV-53401' do
  title 'SQL Server must have allocated audit record storage capacity to meet the organization-defined requirements for saving audit record information.'
  desc 'SQL Server does not have the ability to be cognizant of potential audit log storage capacity issues. During the installation and/or configuration process, SQL Server should detect and determine if adequate storage capacity has been allocated for audit logs.

During the installation process, a notification may be provided to the installer indicating, based on the auditing configuration chosen and the amount of storage space allocated for audit logs, the amount of storage capacity available is not sufficient to meet storage requirements. SQL Server is not able to send out notice based on adequate storage capacity allocated for the audit logs.'
  desc 'check', 'From a Command Prompt, open fsrm.msc.
If fsrm.msc is not installed, the File Server Resource Manager is not installed; File and Folder Quota Management is not enabled. If File Server Resource Manager or a third-party tool capable of sending alert notifications based on audit log store requirements is not installed, this is a finding.

If fsrm.msc is installed, expand File Server Resource Manager in the left pane.
Expand Quota Management.
Expand Quotas.
If Quotas have not been created for defined Audit Log storage locations, this is a finding.'
  desc 'fix', 'Use File Server Resource Manager (FSRM.msc) to enable File and Folder Quota Management and create quotas for identified Audit storage locations.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47643r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41026'
  tag rid: 'SV-53401r2_rule'
  tag stig_id: 'SQL2-00-010600'
  tag gtitle: 'SRG-APP-000072-DB-000046'
  tag fix_id: 'F-46325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
