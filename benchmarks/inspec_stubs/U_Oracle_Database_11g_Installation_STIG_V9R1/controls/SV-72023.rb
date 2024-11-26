control 'SV-72023' do
  title 'A minimum of two Oracle redo log groups/files must be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID device.'
  desc 'The Oracle redo log files store the detailed information on changes made to the database. This information is critical to database recovery in case of a database failure.'
  desc 'check', 'From SQL*Plus:

select count(*) from V$LOG;
If the value of the count returned is less than 2, this is a finding.

From SQL*Plus:

select count(*) from V$LOG where members > 1;
If the value of the count returned is less than 2 and a RAID storage device is not being used, this is a finding.'
  desc 'fix', "To define additional redo log file groups:

From SQL*Plus (Example):
alter database add logfile group 2 ('diska:log2.log', 'diskb:log2.log') size 50K;

To add additional redo log file [members] to an existing redo log file group:

From SQL*Plus (Example):
alter database add logfile member 'diskc:log2.log' to group 2;

Replace diska, diskb, diskc with valid, different disk drive specifications. 
Replace log#.log file with valid names for the log files."
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-58447r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57613'
  tag rid: 'SV-72023r1_rule'
  tag stig_id: 'DG7003-ORACLE11'
  tag gtitle: 'Dedicated directories for DBMS redo log'
  tag fix_id: 'F-62815r1_fix'
  tag ia_controls: 'DCPA-1'
end
