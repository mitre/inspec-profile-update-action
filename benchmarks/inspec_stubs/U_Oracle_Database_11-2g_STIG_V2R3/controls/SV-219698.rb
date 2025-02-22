control 'SV-219698' do
  title 'A minimum of two Oracle control files must be defined and configured to be stored on separate, archived disks (physical or virtual) or archived partitions on a RAID device.'
  desc 'Oracle control files are used to store information critical to Oracle database integrity. Oracle uses these files to maintain time synchronization of database files as well as at system startup to verify the validity of system data and log files. Loss of access to the control files can affect database availability, integrity and recovery.'
  desc 'check', 'From SQL*Plus:

select name from v$controlfile;

DoD guidance recommends:

1. A minimum of two distinct control files for each Oracle Database Instance.

2a. Each control file is to be located on separate, archived physical or logical storage devices

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
  impact 0.3
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21423r306943_chk'
  tag severity: 'low'
  tag gid: 'V-219698'
  tag rid: 'SV-219698r401224_rule'
  tag stig_id: 'O112-BP-021500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21422r306944_fix'
  tag 'documentable'
  tag legacy: ['SV-68207', 'V-53967']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
