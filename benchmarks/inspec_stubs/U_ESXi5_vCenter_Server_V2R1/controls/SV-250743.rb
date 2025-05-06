control 'SV-250743' do
  title 'A least-privileges assignment must be used for the Update Manager database user.'
  desc 'Least-privileges mitigates attacks if the Update Manager database account is compromised. The VMware Update Manager requires certain privileges for the database user in order to install, and the installer will automatically check for these. The privileges on the VUM database user must be reduced for normal operation.'
  desc 'check', 'Verify only the following permissions are allowed to the VUM DB user after installation.

For Oracle DB normal operation, only the following permissions are required. 
Create session
create any table
drop any table

For SQL Server DB normal operation, the dba_owner role or sysadmin role can be removed from the MSDB database. The dba_owner role or sysadmin role is still required for the Update Manager database.

Note: While current, it is always best to check both the latest VMware Update Manager Administration Guide and the vendor database documentation for any updates to these configurations.

If the above vendor database-dependent permissions are not strictly adhered to, this is a finding.'
  desc 'fix', 'For Oracle DB normal runtime operation, set the following permissions. 
Create session
create any table
drop any table

For SQL Server DB normal runtime operation remove/delete the dba_owner role or sysadmin role from the MSDB database. The dba_owner role or sysadmin role is still required for the Update Manager database.

Note: While current, it is always best to check both the latest VMware Update Manager Administration Guide and the vendor database documentation for any updates to these configurations.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54178r799917_chk'
  tag severity: 'medium'
  tag gid: 'V-250743'
  tag rid: 'SV-250743r799919_rule'
  tag stig_id: 'VCENTER-000024'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54132r799918_fix'
  tag 'documentable'
  tag legacy: ['V-39562', 'SV-51420']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
