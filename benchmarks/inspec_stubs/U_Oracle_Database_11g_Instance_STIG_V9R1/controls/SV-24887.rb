control 'SV-24887' do
  title 'A minimum of two Oracle control files should be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID device.'
  desc 'Oracle control files are used to store information critical to Oracle database integrity. Oracle uses these files to maintain time synchronization of database files as well as at system startup to verify the validity of system data and log files. Loss of access to the control files can affect database availability, integrity and recovery.'
  desc 'check', 'From SQL*Plus:

  select name from v$controlfile;

DoD guidance recommends:

1. A minimum of two distinct control files for each Oracle Database Instance.
2a. Each control file is to be located on separate, archived physical storage devices

OR

2b. Each control file is to be located on separate, archived directories within one or more RAID devices 

3. The Logical Paths for each control file should differ at the highest level supported by your configuration, for example:

UNIX
/ora03/app/oracle/{SID}/control/control01.ctl
/ora04/app/oracle/{SID}/control/control02.ctl

Windows
D:/oracle/{SID}/control/control01.ctl
E:/oracle/{SID}/control/control02.ctl

If this minimum listed above is not met, this is a Finding.

Consult with the SA or DBA to determine that the mount points or partitions referenced in the file paths indicate separate physical disks or directories on RAID devices.

NOTE: Distinct does not equal dedicated. You may share directory space with other Oracle database instances if present.'
  desc 'fix', "To prevent loss of service during disk failure, multiple copies of Oracle control files should be maintained on separate disks in archived directories or on separate, archived directories within one or more RAID devices.

Adding or moving a control file requires careful planning and execution.

Please consult and follow the instructions for creating control files in the Oracle Database Administrator's Guide, under Steps for Creating New Control Files."
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29439r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2521'
  tag rid: 'SV-24887r1_rule'
  tag stig_id: 'DO0260-ORACLE11'
  tag gtitle: 'Oracle control file availability'
  tag fix_id: 'F-26497r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
