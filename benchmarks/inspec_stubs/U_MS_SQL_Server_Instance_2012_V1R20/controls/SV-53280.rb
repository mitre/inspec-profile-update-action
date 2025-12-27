control 'SV-53280' do
  title 'SQL Server backups of system-level information per organization-defined frequency must be performed that is consistent with recovery time and recovery point objectives.'
  desc 'SQL Server backups are a critical step in maintaining data assurance and availability.

System-level information includes:  system-state information, operating system and application software, and licenses.

Backups shall be consistent with organizationally defined recovery time and recovery point objectives.

SQL Server depends upon the availability and integrity of its system-level information. Without backups, compromise or loss of system-level information can prevent a successful recovery of SQL Server operations. If SQL Server system-level information is not backed up regularly this risks the loss of SQL Server data in the event of a system failure.

A mixture of full and incrementally server level backups that backup the system-level information would satisfy this requirement.'
  desc 'check', 'Windows Server Backup, or a 3rd Party Backup Tool, can be utilized to perform this function. Determine how SQL Server is being backed up. If there is no scheduled backup or if organizationally defined backup policy and procedures does not exist, this is finding.

Check evidence of inclusion of system-level information into current backup records, if the organizationally defined backup policy, procedures, and backup configurations is not including system-level information backups, this is a finding.'
  desc 'fix', 'Deploy a backup solution to perform backups as per organizationally defined Backup Policy.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47581r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40926'
  tag rid: 'SV-53280r2_rule'
  tag stig_id: 'SQL2-00-018200'
  tag gtitle: 'SRG-APP-000146-DB-000099'
  tag fix_id: 'F-46208r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000537']
  tag nist: ['CP-9 (b)']
end
