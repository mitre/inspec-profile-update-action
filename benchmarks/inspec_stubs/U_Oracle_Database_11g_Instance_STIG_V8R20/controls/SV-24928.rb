control 'SV-24928' do
  title 'Required object auditing should be configured.'
  desc 'Database object definitions and configurations require similar oversight as application libraries to detect unauthorized changes. Unauthorized changes may indicate attempts to compromise data or application object integrity or confidentiality. Any access to audit data objects stored in the database must be audited to detect any attempts to compromise the audit trail. A compromise to audit data could jeopardize accountability for unauthorized actions.'
  desc 'check', "From SQL*Plus:

  select count(*) from all_def_audit_opts where ren = 'A/A';

If the count of 0 is returned, this is a Finding.

Check for required auditing of the audit table as follows:

From SQL*Plus:

  select upd, del, object_type from dba_obj_audit_opts
  where object_name = 'AUD$';

If the record returned is of object type TABLE and upd(ate) and del(ete) are not = 'A/A', this is a Finding.

If the record type VIEW is returned and upd and del are = ‘A/A’, this is NOT a Finding.

Otherwise, if the record type VIEW is returned and upd and del are NOT = 'A/A', then the underlying table must be checked for update and delete auditing as follows:

From SQL*Plus:

  set long 1000
  set wrap on
  select text from dba_views where view_name = 'AUD$';

Review the text returned and locate the “from table_owner.table_name”. This should be located at the end of the text returned.

Replace table_owner and table_name in the select statement below with the values returned above.

From SQL*Plus:

  select upd, del from dba_obj_audit_opts 
  where owner = 'table_owner' and object_name = 'table_name';

If the value of upd(ate) and del(ete) returned above is NOT equal to 'A/A', this is a Finding."
  desc 'fix', 'The only application objects auditing required is for use of the RENAME privilege on database objects.

Configure auditing on RENAME privilege use by default for newly created objects.

From SQL*Plus:

  audit rename on default by access;

If application objects have already been created, the audit rename on object statement should be issued for all application objects.

From SQL*Plus:

  audit rename on [application object name] by access;

Enable auditing of access and activity on audit trail data stored in the database.

From SQL*Plus:

  audit update, delete on AUD$ by access;

NOTE:  The audit table is by default in the SYSTEM schema, but may have been moved to another schema.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29477r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2562'
  tag rid: 'SV-24928r2_rule'
  tag stig_id: 'DO3610-ORACLE11'
  tag gtitle: 'Oracle minimum object auditing'
  tag fix_id: 'F-26541r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
