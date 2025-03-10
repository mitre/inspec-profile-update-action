control 'SV-243095' do
  title 'The vCenter Server must use a least-privileges assignment for the vCenter Server database user.'
  desc 'Least privileges mitigate attacks if the vCenter database account is compromised. vCenter requires very specific privileges on the database. Privileges normally required only for installation and upgrade must be removed for/during normal operation. These privileges may be reinstated if/when any future upgrade must be performed.'
  desc 'check', 'Note: For vCenter Server Appliance, this is not applicable.

Verify that only the following permissions are allowed on the vCenter database for the following roles and users. 

vCenter database administrator role used only for initial setup and periodic maintenance of the database: 

Schema permissions: ALTER, REFERENCES, and INSERT. 
Permissions CREATE TABLE, CREATE VIEW, and CREATE PROCEDURE 

vCenter database user role: 

Schema permissions: SELECT, INSERT, DELETE, UPDATE, and EXECUTE

EXECUTE permissions on sp_add_job, sp_delete_job, sp_add_jobstep, sp_update_job, sp_add_jobserver, sp_add_jobschedule, and sp_add_category stored procedures. 

SELECT permission on syscategories, sysjobsteps, sysjobs_view, and sysjobs tables. 

vCenter database user: 

VIEW SERVER STATE and VIEW ANY DEFINITIONS. 

Equivalent permissions must be set for non-MSSQL databases. 

If the above database permissions are not set correctly, this is a finding.

If the database user role is not assigned to the database account after installation, this is a finding.

If the embedded Postgres database is used, this finding is not applicable.

For more information, refer to the following website: https://docs.vmware.com/en/VMware-vSphere/6.7/com.vmware.vcenter.install.doc/GUID-66638880-75B5-446E-BD8C-0230FECF60E0.html'
  desc 'fix', 'Configure correct permissions and roles for SQL: 

Grant these privileges to a vCenter database administrator role used only for initial setup and periodic maintenance of the database: 

Schema permissions ALTER, REFERENCES, and INSERT. 
Permissions CREATE TABLE, VIEW, and CREATE PROCEDURES 

Grant these privileges to a vCenter database user role: 

SELECT, INSERT, DELETE, UPDATE, and EXECUTE
 
EXECUTE permissions on sp_add_job, sp_delete_job, sp_add_jobstep, sp_update_job, sp_add_jobserver, sp_add_jobschedule, and sp_add_category stored procedures. 

SELECT permission on syscategories, sysjobsteps, sysjobs_view, and sysjobs tables. 

Grant the permissions VIEW SERVER STATE and VIEW ANY DEFINITIONS to the vCenter database user. 

For more information, refer to the following website: https://docs.vmware.com/en/VMware-vSphere/6.7/com.vmware.vcenter.install.doc/GUID-66638880-75B5-446E-BD8C-0230FECF60E0.html'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46370r719526_chk'
  tag severity: 'medium'
  tag gid: 'V-243095'
  tag rid: 'SV-243095r719528_rule'
  tag stig_id: 'VCTR-67-000033'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46327r719527_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
