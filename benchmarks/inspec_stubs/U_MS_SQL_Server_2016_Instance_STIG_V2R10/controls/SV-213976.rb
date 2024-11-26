control 'SV-213976' do
  title 'SQL Server must prevent unauthorized and unintended information transfer via Instant File Initialization (IFI).'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.'
  desc 'check', 'Review the system documentation to determine if Instant File Initialization (IFI) is required.

If IFI is documented as required, this is not a finding.

Review system configuration to determine whether IFI support has been enabled (by default in SQL Server 2016).

Start >> Control Panel >> Administrative Tools >> Local Security Policy >> Local Policies >> User Rights Assignment

If the SQL Service SID (Default instance: NT SERVICE\\MSSQLSERVER. Named instance: NT SERVICE\\MSSQL$InstanceName) has been granted "Perform volume maintenance tasks" Local Rights Assignment and if it is not documented in the system documentation, this is a finding.'
  desc 'fix', 'If IFI is not documented as being required, disable instant file initialization for the instance of SQL Server by removing the SQL Service SID and/or service account from the "Perform volume maintenance tasks" Local Rights Assignment.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15193r313711_chk'
  tag severity: 'medium'
  tag gid: 'V-213976'
  tag rid: 'SV-213976r917655_rule'
  tag stig_id: 'SQL6-D0-009900'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-15191r313712_fix'
  tag 'documentable'
  tag legacy: ['SV-93919', 'V-79213']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
