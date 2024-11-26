control 'SV-219827' do
  title 'A minimum of two Oracle control files must be defined and configured to be stored on separate, archived disks (physical or virtual) or archived partitions on a RAID device.'
  desc 'Oracle control files are used to store information critical to Oracle database integrity. Oracle uses these files to maintain time synchronization of database files as well as at system startup to verify the validity of system data and log files. Loss of access to the control files can affect database availability, integrity and recovery.'
  desc 'check', 'From SQL*Plus:

  select name from v$controlfile;

DoD guidance recommends:

2a. Each control file is to be located on separate, archived physical or virtual storage devices.

OR

2b. Each control file is to be located on separate, archived directories within one or more RAID devices. 

3. The Logical Paths for each control file should differ at the highest level supported by the configuration, for example:

UNIX
/ora03/app/oracle/{SID}/control/control01.ctl
/ora04/app/oracle/{SID}/control/control02.ctl

Windows
D:/oracle/{SID}/control/control01.ctl
E:/oracle/{SID}/control/control02.ctl

If the minimum listed above is not met, this is a finding.

Consult with the SA or DBA to determine that the mount points or partitions referenced in the file paths indicate separate physical disks or directories on RAID devices.

Note: Distinct does not equal dedicated. May share directory space with other Oracle database instances if present.'
  desc 'fix', "To prevent loss of service during disk failure, multiple copies of Oracle control files must be maintained on separate disks in archived directories or on separate, archived directories within one or more RAID devices.

Adding or moving a control file requires careful planning and execution.

Consult and follow the instructions for creating control files in the Oracle Database Administrator's Guide, under Steps for Creating New Control Files."
  impact 0.3
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21538r533020_chk'
  tag severity: 'low'
  tag gid: 'V-219827'
  tag rid: 'SV-219827r533022_rule'
  tag stig_id: 'O121-BP-021500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21537r533021_fix'
  tag 'documentable'
  tag legacy: ['SV-75907', 'V-61417']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
