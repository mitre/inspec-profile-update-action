control 'SV-53399' do
  title 'SQL Server auditing configuration maximum number of files must be configured to reduce the likelihood of storage capacity being exceeded, while meeting organization-defined auditing requirements.'
  desc 'Configure SQL Server during the installation and/or configuration process to determine if adequate storage capacity has been allocated for audit logs.

If SQL Server audit logs that are being generated exceed the amount of space reserved for those logs, the system may shutdown or take other measures to stop processing in order to protect transactions from continuing unlogged.

After the initial setup of SQL Server audit log configuration, it is best to check the available space frequently until the maximum number of files has been reached. Checking the available space can help determine the balance of online audit data with space required.'
  desc 'check', 'Check the SQL Server audit setting on the maximum number of files of the trace used for the auditing requirement. 

Select * from sys.traces. Determine the audit being used to fulfill the overall auditing requirement. Examine the max_files and max_size parameters. SQL will overwrite the oldest files when the max_files parameter has been exceeded. Care must be taken to ensure that this does not happen, or data will be lost. 


The amount of space determined for logging by SQL Server is calculated by multiplying the maximum number of files by the maximum file size.   
If auditing will outgrow the space reserved for logging before being overwritten, this is a finding.'
  desc 'fix', 'Configure the maximum number of audit log files that are to be generated, staying within the number of logs the system was sized to support.

Update the max_files parameter of the audits to ensure the correct number of files is defined.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47641r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41024'
  tag rid: 'SV-53399r2_rule'
  tag stig_id: 'SQL2-00-010500'
  tag gtitle: 'SRG-APP-000071-DB-000047'
  tag fix_id: 'F-46323r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
