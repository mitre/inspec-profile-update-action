control 'SV-24694' do
  title 'ccess to external objects should be disabled if not required and authorized.'
  desc 'The UTL_FILE package allows host file access from within the database using the permissions and privileges assigned to the Oracle database process or service. This package should be used with caution. All files accessible to using this package is equally accessible to any database user with execute permissions to the UTL_FILE package. When UTL_FILE_DIR is set to “*”, all directories accessible to the Oracle database process, typically the Oracle installation account, are accessible via the UTL_FILE package. This setting effectively turns off directory access checking, and makes any directory accessible to the UTL_FILE functions. The UTL_FILE_DIR list should specify only authorized and protected directories and should include only fully specified path names.'
  desc 'check', "From SQL*Plus:
  select value from v$parameter where name='utl_file_dir';

If the returned value contains '*', this is a Finding."
  desc 'fix', 'Where its use is authorized, restrict access by a database session to external host files.

From SQL*Plus:
  alter system set utl_file_dir=[authorized directory] scope=spfile;

Replace [authorized directory] with the directory path where file access and storage is authorized.

Review Oracle MetaLink Note 39037.1 if you need to define multiple authorized directories.

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-19611r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15617'
  tag rid: 'SV-24694r1_rule'
  tag stig_id: 'DG0098-ORACLE11'
  tag gtitle: 'DBMS access to external local objects'
  tag fix_id: 'F-2614r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
