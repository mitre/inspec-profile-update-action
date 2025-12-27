control 'SV-235174' do
  title 'The MySQL Database Server 8.0 must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'Review the system documentation for a description of how audit records are off-loaded.

Check that the OS or software is in place to copy or transfer the specified audit record content to a centralized audit log repository. If it is not, this is a finding.

Check that permissions are set on the either the MySQL audit log read functions (users granted AUDIT_ADMIN or MySQL Audit Files and on the target repository to enable the required transfer of audit data. If not, this is a finding.

Verify that the specified audit record content is indeed copied or transferred to the central repository. If it is not, this is a finding.'
  desc 'fix', 'If necessary, employ SQL code calls to the audit log read functions or other software to copy or transfer the specified audit record content to the repository.

Ensure that permissions are set to enable transfer of the data. Some SQL may require the AUDIT_ADMIN permission be granted to the MySQL user account used for transferring the data.

Based on the setup, allocate sufficient audit file/table space to support peak demand.

For example to set to 1 GB:
set persist audit_log_rotate_on_size=1024*1024*1024;

If using file copies to move audit logs, only audit.<timestamp>.log* formatted files should be copied as audit.log* are still being written to.

If audit data is copied using a SQL function, the audit files still require removal using some alternative method on the OS filesystem, for example a third-party tool or a scheduled script.

If, after the preceding steps, the transfer is not succeeding, diagnose and repair the problem.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38393r623642_chk'
  tag severity: 'medium'
  tag gid: 'V-235174'
  tag rid: 'SV-235174r623644_rule'
  tag stig_id: 'MYS8-00-009700'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-38356r623643_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
