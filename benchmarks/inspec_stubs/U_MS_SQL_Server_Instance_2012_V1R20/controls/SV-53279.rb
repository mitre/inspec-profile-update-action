control 'SV-53279' do
  title 'SQL Server software libraries must be periodically backed up.'
  desc 'SQL Server backups are a critical step in maintaining data assurance and availability.

System-level information includes system-state information, operating system and application software, and licenses.

Backups shall be consistent with organization-defined recovery time and recovery point objectives.

SQL Server depends upon the availability and integrity of its software libraries. Without backups, compromise or loss of the software libraries can prevent a successful recovery of SQL Server operations.

A mixture of full and incremental server-level backups by a third-party tool that backs up those software library directories would satisfy this requirement.'
  desc 'check', 'Review evidence of inclusion of SQL Server software libraries in current backup records.
If the backup tool does not include SQL Server, this is a finding.'
  desc 'fix', 'Ensure inclusion of all SQL Server software libraries into the backup process.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47580r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40925'
  tag rid: 'SV-53279r2_rule'
  tag stig_id: 'SQL2-00-018300'
  tag gtitle: 'SRG-APP-000146-DB-000100'
  tag fix_id: 'F-46207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000537']
  tag nist: ['CP-9 (b)']
end
