control 'SV-24363' do
  title 'Application software should be owned by a Software Application account.'
  desc 'File and directory ownership imparts full privileges to the owner. These privileges should be restricted to a single, dedicated account to preserve proper chains of ownership and privilege assignment management.'
  desc 'check', 'Ask the DBA/SA to demonstrate file and group ownership of the Oracle DBMS software and files and directories.

On Windows systems:

Launch a Windows Explorer window. In the Right Pane, Right-Click on one of the display headers and select Owner from the list. Move the Owner column after the Name column. Size the Owner column to fit the current contents.

NOTE: This will show the owner column for this folder only. If you want to see the owner column in all folders, select Tools -> Options -> View tab and click on the Apply to All Folders button.

The Oracle DBMS software is usually installed using an account with administrator privileges and ownership is assigned either to the account used to install the DBMS software or to the Administrators group.

For DBMS systems with multiple Oracle Homes using a common Oracle Base, ensure an ownership review for files and directories in the %ORACLE_BASE% that are not addressed above is performed.

If any files or directories belonging to an Oracle DBMS software installation are not owned by a dedicated Oracle OS owner account, this is a Finding.

On UNIX systems:

find $ORACLE_HOME /var/opt/oracle /etc/ora* /usr/local/bin/*ora*  usr/local/bin/db* ! -user oracle -o ! -group oinstall | xargs ls -lR -d

Where "oracle" is the known Oracle Owner account name and "oinstall" is the known Oracle Group account name.

Review the resulting output and note the file/directory ownership.

For DBMS systems with multiple Oracle Homes using a common Oracle Base, ensure an ownership review for files and directories in the %ORACLE_BASE% that are not addressed above is performed.

If any files or directories belonging to an Oracle DBMS software installation are not owned by a dedicated Oracle OS owner account, this is a Finding.

The owner and group ownership as well as file permissions for the following files (if present) should not be changed:
  extjob
  jssu
  nmb
  nmhs
  nmo
  oradism
  externaljob.ora
  coraenv
  dbhome
  oraenv'
  desc 'fix', 'Assign DBMS file and directory ownership to a dedicated Oracle OS owner account.

Document the locations of Oracle DBMS files and directories in the System Security Plan.

On Windows systems:

The creation of a dedicated Oracle OS account and change of ownership of all files in the %ORACLE_HOME% directories and subdirectories should be performed prior to placing the DBMS system into production.

See checks DO0120 and DG0102 for details on establishing a dedicated OS account for Oracle services on Windows platforms.

Using the dedicated Oracle OS owner account to install and maintain the DBMS software libraries and configuration files will help maintain file and directory ownership.

On UNIX systems:

Assign DBMS file and directory ownership to a dedicated Oracle host OS software installation and maintenance account.

The owner and group ownership as well as file permissions for the following files (if present) should not be changed:

extjob
jssu
nmb
nmhs
nmo
oradism
externaljob.ora
coraenv
dbhome
oraenv

Using the dedicated Oracle host OS software installation and maintenance account to install and maintain the DBMS software libraries and configuration files will help maintain file and directory ownership.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29106r1_chk'
  tag severity: 'low'
  tag gid: 'V-3805'
  tag rid: 'SV-24363r1_rule'
  tag stig_id: 'DG0019-ORACLE11'
  tag gtitle: 'DBMS software ownership'
  tag fix_id: 'F-26109r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
