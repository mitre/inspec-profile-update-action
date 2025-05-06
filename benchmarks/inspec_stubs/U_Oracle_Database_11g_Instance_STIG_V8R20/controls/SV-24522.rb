control 'SV-24522' do
  title 'A minimum of two Oracle redo log groups/files should be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID device.'
  desc 'The Oracle redo log files store the detailed information on changes made to the database. This information is critical to database recovery in case of a database failure.'
  desc 'check', 'From SQL*Plus:

  select count(*) from V$LOG;

If the value of the count returned is less than 2, this is a Finding.

From SQL*Plus:

  select count(*) from V$LOG where members > 1;

If the value of the count returned is less than 2 and a RAID storage device is not being used, this is a Finding.'
  desc 'fix', "To define additional redo log file groups:

From SQL*Plus (Example):

  alter database add logfile group 2 
    ('diska:log2.log' ,  
     'diskb:log2.log') size 50K; 

To add additional redo log file [members] to an existing redo log file group:

From SQL*Plus (Example):

  alter database add logfile member 'diskc:log2.log'
  to group 2;

Replace diska, diskb, diskc with valid, different disk drive specifications.

Replace log#.log file with valid or custom names for the log files."
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29441r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2522'
  tag rid: 'SV-24522r2_rule'
  tag stig_id: 'DO0270-ORACLE11'
  tag gtitle: 'Oracle redo log file availability'
  tag fix_id: 'F-26500r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
