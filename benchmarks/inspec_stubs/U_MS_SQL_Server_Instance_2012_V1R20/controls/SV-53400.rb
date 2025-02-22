control 'SV-53400' do
  title 'SQL Server auditing configuration maximum file size must be configured to reduce the likelihood of storage capacity being exceeded, while meeting organization-defined auditing requirements.'
  desc 'Configure SQL Server during the installation and/or configuration process to determine if adequate storage capacity has been allocated for audit logs.

If SQL Server audit logs that are being generated exceed the amount of space reserved for those logs, the system may shutdown or take other measures to stop processing in order to protect transactions from continuing unlogged.

After the initial setup of SQL Server audit log configuration, it is best to check the available space until the maximum number of files has been reached. SQL will overwrite the oldest files when the max_files parameter has been exceeded. Care must be taken to ensure that this does not happen, or data will be lost. Therefore, the combination of max_size and max_files must be monitored to ensure that overwriting does not occur. This must also coincide with the backup process of off-loading the files.'
  desc 'check', 'Check the SQL Server audit setting on the maximum file size of the trace used for the auditing requirement. 

Select * from sys.traces. Determine the audit being used to fulfill the overall auditing requirement. Examine the max_files and max_size parameters. SQL will overwrite the oldest files when the max_files parameter has been exceeded. Care must be taken to ensure that this does not happen, or data will be lost. 


The amount of space determined for logging by SQL Server is calculated by multiplying the maximum number of files by the maximum file size.   
If auditing will outgrow the space reserved for logging before being overwritten, this is a finding.'
  desc 'fix', 'Configure the maximum file size of each audit log file that is to be generated, staying within the file size the system was sized to support. Modify the audit in question to be placed on drives with adequate space or reconfigure to ensure the audit will not fill the space allocated.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47642r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41025'
  tag rid: 'SV-53400r2_rule'
  tag stig_id: 'SQL2-00-010400'
  tag gtitle: 'SRG-APP-000071-DB-000047'
  tag fix_id: 'F-46324r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
