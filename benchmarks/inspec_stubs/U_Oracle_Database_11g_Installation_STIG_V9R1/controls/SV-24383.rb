control 'SV-24383' do
  title 'Database software, applications and configuration files should be monitored to discover unauthorized changes.'
  desc 'Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review documented software and configuration monitoring procedures and implementation evidence to verify that monitoring of changes to database software libraries, related applications and configuration files is being performed weekly or more often.

Verify that a list of files and directories being monitored is complete.

If monitoring is not being performed weekly or more often, this is a Finding.

If implementation evidence is not complete, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures to monitor for unauthorized changes to DBMS software libraries, related software application libraries and configuration files.

If a third-party automated tool is not employed, an automated job that reports file information on the directories and files of interest and compares them to the baseline report for the same will meet the requirement.

File hashes or checksums should be used for comparisons as file dates may be manipulated by malicious users.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2423'
  tag rid: 'SV-24383r1_rule'
  tag stig_id: 'DG0050-ORACLE11'
  tag gtitle: 'DBMS software and configuration file monitoring'
  tag fix_id: 'F-26156r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
