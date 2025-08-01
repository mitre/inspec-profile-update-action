control 'SV-219723' do
  title 'Application object owner accounts must be disabled when not performing installation or maintenance actions.'
  desc 'Object ownership provides all database object permissions to the owned object. Access to the application object owner accounts requires special protection to prevent unauthorized access and use of the object ownership privileges. In addition to the high privileges to application objects assigned to this account, it is also an account that, by definition, is not accessed interactively except for application installation and maintenance. This reduced access to the account means that unauthorized access to the account could go undetected. To help protect the account, it should be enabled only when access is required.'
  desc 'check', "Run the SQL query:

select distinct o.owner from dba_objects o, dba_users u
 where o.owner not in
(
 <list of non-applicable accounts>
)
 and o.object_type <> 'SYNONYM'
 and o.owner = username
 and upper(account_status) not like '%LOCKED%';

(With respect to the list of special accounts that are excluded from this requirement, it is expected that the DBA will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.)

To obtain a list of users assigned DBA privileges, run the query:

select grantee from dba_role_privs where granted_role = ’DBA’;

If any records are returned, then verify the account is an authorized application object owner account or a default account installed to support an Oracle product.  

Verify that any objects owned by custom DBA accounts are for the personal use of that DBA.

If any objects are used to support applications or any functions other than DBA functions, this is a Finding.

Any unauthorized object owner accounts are not a finding under this check as they are noted as findings under check O112-C2-011000.  

Any other accounts listed are a Finding."
  desc 'fix', 'Disable any application object owner accounts.

From SQL*Plus:
alter user [username] account lock;

Enable application object owner accounts only for installation and maintenance.

DBA are special purpose accounts and do not require disabling although they may own objects.

For application objects that require routine maintenance, e.g. index objects, to maintain performance, consider allowing a special purpose account to own the index or enable the application owner account for the duration of the routine maintenance function only.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21448r307018_chk'
  tag severity: 'medium'
  tag gid: 'V-219723'
  tag rid: 'SV-219723r401224_rule'
  tag stig_id: 'O112-BP-024000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21447r307019_fix'
  tag 'documentable'
  tag legacy: ['SV-68257', 'V-54017']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
