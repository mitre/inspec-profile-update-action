control 'SV-219849' do
  title 'The directories assigned to the LOG_ARCHIVE_DEST* parameters must be protected from unauthorized access.'
  desc 'The LOG_ARCHIVE_DEST parameter is used to specify the directory to which Oracle archive logs are written. Where the DBMS availability and recovery to a specific point in time is critical, the protection of archive log files is critical. Archive log files may also contain unencrypted sensitive data. If written to an inadequately protected or invalidated directory, the archive log files may be accessed by unauthorized persons or processes.'
  desc 'check', "From SQL*Plus:

  select log_mode from v$database;
  select value from v$parameter where name = 'log_archive_dest';
  select value from v$parameter where name = 'log_archive_duplex_dest';
  select name, value from v$parameter where name LIKE 'log_archive_dest_%';
  select value from v$parameter where name = 'db_recovery_file_dest';

If the value returned for LOG_MODE is NOARCHIVELOG, this check is not a finding.

If a value is not returned for LOG_ARCHIVE_DEST and no values are returned for any of the LOG_ARCHIVE_DEST_[1-10] parameters, and no value is returned for DB_RECOVERY_FILE_DEST, this is a finding.

Note: LOG_ARCHIVE_DEST and LOG_ARCHIVE_DUPLEX_DEST are incompatible with the LOG_ARCHIVE_DEST_n parameters, and must be defined as the null string (' ') when any LOG_ARCHIVE_DEST_n parameter has a value other than a null string.

On UNIX Systems:

  ls -ld [pathname]

Substitute [pathname] with the directory paths listed from the above SQL statements for log_archive_dest and log_archive_duplex_dest.

If permissions are granted for world access, this is a finding.

On Windows Systems (From Windows Explorer):

Browse to the directory specified.

Select and right-click on the directory, select Properties, select the Security tab.

If permissions are granted to everyone, this is a finding.

If any account other than the Oracle process and software owner accounts, Administrators, DBAs, System group or developers authorized to write and debug applications on this database are listed, this is a finding."
  desc 'fix', 'Specify a valid and protected directory for archive log files.

Restrict access to the Oracle process and software owner accounts, DBAs, and backup operator accounts.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21560r533082_chk'
  tag severity: 'medium'
  tag gid: 'V-219849'
  tag rid: 'SV-219849r401224_rule'
  tag stig_id: 'O121-BP-023800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21559r533083_fix'
  tag 'documentable'
  tag legacy: ['SV-75953', 'V-61463']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
