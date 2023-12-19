control 'SV-237747' do
  title 'Oracle Database must off-load audit data to a separate log management facility; this must be continuous and in near-real-time for systems with a network connection to the storage facility, and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, files in the file system, other kinds of local repositories, or a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'Review the system documentation for a description of how audit records are off-loaded.

If the DBMS has a continuous network connection to the centralized log management system, but the DBMS audit records are not written directly to the centralized log management system or transferred in near-real-time, this is a finding.

If the DBMS does not have a continuous network connection to the centralized log management system, and the DBMS audit records are not transferred to the centralized log management system weekly or more often, this is a finding.'
  desc 'fix', 'Configure the DBMS or deploy and configure software tools to transfer audit records to a centralized log management system, continuously and in near-real-time where a continuous network connection to the log management system exists, or at least weekly in the absence of such a connection.

For more information on auditing, refer to the following documents:

https://docs.oracle.com/database/121/DBSEG/auditing.htm#DBSEG1024'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40966r667271_chk'
  tag severity: 'medium'
  tag gid: 'V-237747'
  tag rid: 'SV-237747r667273_rule'
  tag stig_id: 'O121-P2-008100'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-40929r667272_fix'
  tag 'documentable'
  tag legacy: ['V-61871', 'SV-76361']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
