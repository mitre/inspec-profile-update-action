control 'SV-24419' do
  title 'DBMS system data files should be stored in dedicated disk directories.'
  desc 'DBMS system data files have different access control requirements than application data and log files. Granting access to system data files beyond those required for system operations could lead to a compromise of the DBMS integrity or disclosure of sensitive data.'
  desc 'check', "From SQL*Plus:
  select file_name from dba_data_files
  where tablespace_name='SYSTEM';

NOTE: Data files for a given database instance may include data files (*.dbf), REDO log files (redo*.log) and CONTROL files (*.ctl).

Review the files in the directory shown above.

Allowable files are instance database files (*.dbf), REDO log files (redo*.log) and CONTROL files (*.ctl).

If any files other than these exist in the directory, this is a Finding.

A good best practice (not consistently endorsed by the Oracle community) is on database creation, using separate subdirectories for data, redo and control files [under the instance name directory] instead of using a single directory to contain all Oracle data, redo and control instance files."
  desc 'fix', 'Create a dedicated directory or dedicated subdirectories to store database instance files.

Reconfigure the Oracle instance to point to the files in the new locations.

Where feasible, locate database instance files on a dedicated disk partition and/or RAID device to provide additional protection.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-948r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15623'
  tag rid: 'SV-24419r1_rule'
  tag stig_id: 'DG0112-ORACLE11'
  tag gtitle: 'DBMS system data file protection'
  tag fix_id: 'F-3414r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
