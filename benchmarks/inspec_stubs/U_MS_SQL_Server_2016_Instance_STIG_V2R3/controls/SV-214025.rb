control 'SV-214025' do
  title 'The system SQL Server must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Off-loading is a common process in information systems with limited audit storage capacity. 
 
The system SQL Server may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'Review the system documentation for a description of how audit records are off-loaded. 
 
If the system has a continuous network connection to the centralized log management system, but the DBMS audit records are not written directly to the centralized log management system or transferred in near-real-time, this is a finding. 
 
If the system does not have a continuous network connection to the centralized log management system, and the DBMS audit records are not transferred to the centralized log management system weekly or more often, this is a finding.'
  desc 'fix', 'Configure the system or deploy and configure software tools to transfer audit records to a centralized log management system, continuously and in near-real time where a continuous network connection to the log management system exists, or at least weekly in the absence of such a connection.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15242r313858_chk'
  tag severity: 'medium'
  tag gid: 'V-214025'
  tag rid: 'SV-214025r617437_rule'
  tag stig_id: 'SQL6-D0-015900'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-15240r313859_fix'
  tag 'documentable'
  tag legacy: ['SV-94017', 'V-79311']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
