control 'SV-220306' do
  title 'Database software, applications, and configuration files must be monitored to discover unauthorized changes.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review monitoring procedures and implementation evidence to verify that monitoring of changes to database software libraries, related applications, and configuration files is done.

Verify that the list of files and directories being monitored is complete. If monitoring does not occur or is not complete, this is a finding.'
  desc 'fix', 'Implement procedures to monitor for unauthorized changes to DBMS software libraries, related software application libraries, and configuration files. If a third-party automated tool is not employed, an automated job that reports file information on the directories and files of interest and compares them to the baseline report for the same will meet the requirement.

File hashes or checksums should be used for comparisons since file dates may be manipulated by malicious users.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22021r392049_chk'
  tag severity: 'medium'
  tag gid: 'V-220306'
  tag rid: 'SV-220306r395850_rule'
  tag stig_id: 'O121-OS-010700'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-22013r392050_fix'
  tag 'documentable'
  tag legacy: ['SV-76357', 'V-61867']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
