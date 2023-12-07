control 'SV-224154' do
  title 'Software, applications, and configuration files that are part of, or related to, the Postgres Plus Advanced Server installation must be monitored to discover unauthorized changes.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. Monitoring is required for assurance that the protections are effective.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review monitoring procedures and implementation evidence to verify monitoring of changes to database software libraries, related applications, and configuration files is done.

Verify the list of files and directories being monitored is complete.

If monitoring does not occur or is not complete, this is a finding.'
  desc 'fix', 'Implement procedures to monitor for unauthorized changes to DBMS software libraries, related software application libraries, and configuration files. If a third-party automated tool is not employed, an automated job that reports file information on the directories and files of interest and compares them to the baseline report for the same will meet the requirement.

Use file hashes or checksums for comparisons, as file dates may be manipulated by malicious users.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25827r495482_chk'
  tag severity: 'medium'
  tag gid: 'V-224154'
  tag rid: 'SV-224154r508023_rule'
  tag stig_id: 'EP11-00-003200'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-25815r495483_fix'
  tag 'documentable'
  tag legacy: ['SV-109439', 'V-100335']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
