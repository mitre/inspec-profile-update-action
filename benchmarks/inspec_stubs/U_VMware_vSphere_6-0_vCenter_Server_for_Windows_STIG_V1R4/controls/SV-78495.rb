control 'SV-78495' do
  title 'A least-privileges assignment must be used for the Update Manager database user.'
  desc 'Least-privileges mitigate attacks if the Update Manager database account is compromised. The VMware Update Manager requires certain privileges for the database user in order to install, and the installer will automatically check for these. The privileges on the VUM database user must be reduced for normal operation.'
  desc 'check', 'Verify only the following permissions are allowed to the VUM database user.

For Oracle DB normal operation, only the following permissions are required. 
grant connect to vumAdmin
grant resource to vumAdmin
grant create any job to vumAdmin
grant create view to vumAdmin
grant create any sequence to vumAdmin
grant create any table to vumAdmin
grant lock any table to vumAdmin
grant create procedure to vumAdmin
grant create type to vumAdmin
grant execute on dbms_lock to vumAdmin
grant unlimited tablespace to vumAdmin
# To ensure space limitation is not an issue

For SQL DB normal operation, make sure that the database user has either a sysadmin server role or the db_owner fixed database role on the Update Manager database and the MSDB database.

The db_owner role on the MSDB database is required for installation and upgrade only.

If the above vendor database-dependent permissions are not strictly adhered to, this is a finding.'
  desc 'fix', 'For Oracle DB normal runtime operation, set the following permissions. 
grant connect to vumAdmin
grant resource to vumAdmin
grant create any job to vumAdmin
grant create view to vumAdmin
grant create any sequence to vumAdmin
grant create any table to vumAdmin
grant lock any table to vumAdmin
grant create procedure to vumAdmin
grant create type to vumAdmin
grant execute on dbms_lock to vumAdmin
grant unlimited tablespace to vumAdmin
# To ensure space limitation is not an issue

For SQL DB normal operation, make sure that the database user has either a sysadmin server role or the db_owner fixed database role on the Update Manager database and the MSDB database.

The db_owner role on the MSDB database is required for installation and upgrade only.

Note: While current, it is always best to check both the latest VMware Update Manager Administration Guide and the vendor database documentation for any updates to these configurations.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64005'
  tag rid: 'SV-78495r1_rule'
  tag stig_id: 'VCWN-06-000032'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69935r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
