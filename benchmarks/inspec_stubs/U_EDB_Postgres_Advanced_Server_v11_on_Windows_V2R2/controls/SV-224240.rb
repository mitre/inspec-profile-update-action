control 'SV-224240' do
  title 'The EDB Postgres Advanced Server must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repositories, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'If Postgres Enterprise Manager (PEM) or another log collection tool is not installed and configured to automatically collect audit logs or if or a process for off-loading audit logs to a centralized system is not in place, this is a finding.

Review the system documentation for a description of how audit records are off-loaded and how local audit log space is managed.'
  desc 'fix', 'Install a centralized log-collecting tool and configure it as instructed in its documentation.

If using PEM, find the instructions for configuring the centralized audit manager at:
 https://www.enterprisedb.com/docs/en/7.0/pemgetstarted/toc.html'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25913r495737_chk'
  tag severity: 'medium'
  tag gid: 'V-224240'
  tag rid: 'SV-224240r508023_rule'
  tag stig_id: 'EP11-00-013000'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-25901r495738_fix'
  tag 'documentable'
  tag legacy: ['SV-109613', 'V-100509']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
