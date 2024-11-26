control 'SV-72021' do
  title 'A minimum of two Oracle control files must be defined and configured to be stored on separate, archived disks (physical or virtual) or archived partitions on a RAID device.'
  desc 'Oracle control files are used to store information critical to Oracle database integrity. Oracle uses these files to maintain time synchronization of database files as well as at system startup to verify the validity of system data and log files. Loss of access to the control files can affect database availability, integrity, and recovery.'
  desc 'check', 'From SQL*Plus:
select name from v$controlfile;

DoD guidance recommends:

1. A minimum of two distinct control files for each Oracle Database Instance.
2. Each control file located on separate, archived physical or virtual storage devices.
3. Different Logical Paths for each control file at the highest level supported by your configuration; for example:

UNIX:
/ora03/app/oracle/{SID}/control/control01.ctl
/ora04/app/oracle/{SID}/control/control02.ctl

Windows:
D:/oracle/{SID}/control/control01.ctl
E:/oracle/{SID}/control/control02.ctl

If this minimum is not met, this is a finding.

Verify that the mount points or partitions referenced in the file paths indicate separate physical disks. If not, this is a finding.  

(This includes RAID devices and ASM storage. In the case of SAN storage and where possible, different storage pools must be used for control file locations.  This ensures not only that different physical disks are used but that separate higher level storage components are used.)'
  desc 'fix', 'Establish at least two Oracle control files.  Specify a separate, dedicated disk/directory location for each control file.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-58443r4_chk'
  tag severity: 'low'
  tag gid: 'V-57611'
  tag rid: 'SV-72021r2_rule'
  tag stig_id: 'DG7002-ORACLE11'
  tag gtitle: 'Dedicated directories for DBMS control files'
  tag fix_id: 'F-62811r2_fix'
end
