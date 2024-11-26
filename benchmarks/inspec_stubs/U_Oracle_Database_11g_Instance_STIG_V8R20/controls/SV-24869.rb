control 'SV-24869' do
  title 'The /diag subdirectory under the directory assigned to the DIAGNOSTIC_DEST parameter must be protected from unauthorized access.'
  desc '<0> [object Object]'
  desc 'check', %q(From SQL*Plus:

select value from v$parameter where name='diagnostic_dest';

On UNIX Systems:

ls -ld [pathname]/diag

Substitute [pathname] with the directory path listed from the above SQL command, and append "/diag" to it, as shown.

If permissions are granted for world access, this is a finding.

If any groups that include members other than the Oracle process and software owner accounts, DBAs, auditors, or backup accounts are listed, this is a finding.

On Windows Systems (From Windows Explorer):

Browse to the \diag directory under the directory specified.

Select and right-click on the directory, select Properties, select the Security tab.

If permissions are granted to everyone, this is a finding.

If any account other than the Oracle process and software owner accounts, Administrators, DBAs, System group or developers authorized to write and debug applications on this database are listed, this is a finding.)
  desc 'fix', 'Alter host system permissions to the <DIAGNOSTIC_DEST>/diag directory to the Oracle process and software owner accounts, DBAs, SAs (if required) and developers or other users that may specifically require access for debugging or other purposes.

Authorize and document user access requirements to the directory outside of the Oracle, DBA and SA account list.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-26535r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15747'
  tag rid: 'SV-24869r2_rule'
  tag stig_id: 'DO0233-ORACLE11'
  tag gtitle: 'Oracle DIAGNOSTIC_DEST parameter'
  tag fix_id: 'F-22818r2_fix'
end
