control 'SV-219832' do
  title 'The Oracle SQL92_SECURITY parameter must be set to TRUE.'
  desc 'The configuration option SQL92_SECURITY specifies whether table-level SELECT privileges are required to execute an update or delete that references table column values. If this option is disabled (set to FALSE), the UPDATE privilege can be used to determine values that should require SELECT privileges.

The SQL92_SECURITY setting of TRUE prevents the exploitation of user credentials with only DELETE or UPDATE privileges on a table from being able to derive column values in that table by performing a series of update/delete statements using a where clause, and rolling back the change. In the following example, with SQL92_SECURITY set to FALSE, a user with only delete privilege on the scott.emp table is able to derive that there is one employee with a salary greater than 3000. With SQL92_SECURITY set to TRUE, that user is prevented from attempting to derive a value.

SQL92_SECURITY = FALSE
SQL> delete from scott.emp where sal > 3000;
1 row deleted
SQL> rollback;
Rollback complete

SQL92_SECURITY = TRUE
SQL> delete from scott.emp where sal > 3000;
delete from scott.emp where sal > 3000
                  *
ERROR at line 1:
ORA-01031: insufficient privileges'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'sql92_security';

If the value returned is set to FALSE, this is a finding.

If the parameter is set to TRUE or does not exist, this is not a finding."
  desc 'fix', 'Enable SQL92 security.

From SQL*Plus:

  alter system set sql92_security = TRUE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21543r533035_chk'
  tag severity: 'medium'
  tag gid: 'V-219832'
  tag rid: 'SV-219832r533037_rule'
  tag stig_id: 'O121-BP-022100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21542r533036_fix'
  tag 'documentable'
  tag legacy: ['SV-75919', 'V-61429']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
