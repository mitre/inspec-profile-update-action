control 'SV-213667' do
  title 'The EDB Postgres Advanced Server must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'If Postgres Enterprise Manager (PEM) or another log collection tool is not installed and configured to automatically collect audit logs, this is a finding. 

Review the system documentation for a description of how audit records are off-loaded and how local audit log space is managed.'
  desc 'fix', 'Install PEM and configure the centralized audit manager as documented here: http://www.enterprisedb.com/docs/en/5.0/pemgetstarted/PEM_Getting_Started_Guide.1.32.html#

If another tool other than PEM is used, configure it to meet this requirement.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14889r290313_chk'
  tag severity: 'medium'
  tag gid: 'V-213667'
  tag rid: 'SV-213667r508024_rule'
  tag stig_id: 'PPS9-00-013000'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-14887r290314_fix'
  tag 'documentable'
  tag legacy: ['V-69083', 'SV-83687']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
