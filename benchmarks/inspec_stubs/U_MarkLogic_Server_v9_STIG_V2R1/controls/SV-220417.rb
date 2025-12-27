control 'SV-220417' do
  title 'MarkLogic Server must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', 'Review the system documentation to determine how audit records are offloaded.

If the MarkLogic Server instance is not monitored by a third-party audit management tool, this is a finding.'
  desc 'fix', 'Configure the system to offload MarkLogic audit records.

Add the MarkLogic Server instance under the monitoring of a third-party audit management tool.'
  impact 0.3
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22132r401702_chk'
  tag severity: 'low'
  tag gid: 'V-220417'
  tag rid: 'SV-220417r855498_rule'
  tag stig_id: 'ML09-00-012300'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-22121r401703_fix'
  tag 'documentable'
  tag legacy: ['SV-110181', 'V-101077']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
