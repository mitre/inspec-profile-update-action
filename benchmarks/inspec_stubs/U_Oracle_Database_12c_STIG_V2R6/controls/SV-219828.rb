control 'SV-219828' do
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
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21539r533023_chk'
  tag severity: 'medium'
  tag gid: 'V-219828'
  tag rid: 'SV-219828r533025_rule'
  tag stig_id: 'O121-BP-021600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21538r533024_fix'
  tag 'documentable'
  tag legacy: ['SV-75909', 'V-61419']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
