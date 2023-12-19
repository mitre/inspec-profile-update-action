control 'SV-89249' do
  title 'DB2 must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'Run the following command to find the value of “Audit Data Path” and “Audit Archive Path” 

     $db2audit describe 

DB2 can asynchronously extract the audit records in comma delimited format from “Audit Archive Path”.

If a separate log management facility approved by the organization exists and is configured to absorb the comma delimited audit log files, this is not a finding. 

If a separate log management facility is not configured to absorb the extracted log data, this is a finding.'
  desc 'fix', 'Configure the separate log management facility to absorb audit logs data from comma delimited files produced by extracting the audit data from archived audit logs.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74461r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74575'
  tag rid: 'SV-89249r1_rule'
  tag stig_id: 'DB2X-00-012600'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-81175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
