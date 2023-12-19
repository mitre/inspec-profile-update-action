control 'SV-78497' do
  title 'A least-privileges assignment must be used for the vCenter Server database user.'
  desc 'Least-privileges mitigates attacks if the vCenter database account is compromised. vCenter requires very specific privileges on the database. Privileges normally required only for installation and upgrade must be removed for/during normal operation. These privileges may be reinstated if/when any future upgrade must be performed.'
  desc 'check', 'Verify only the following permissions are allowed on the vCenter database for the following roles and users.

vCenter database administrator role used only for initial setup and periodic maintenance of the database:
Schema permissions ALTER, REFERENCES, and INSERT.
Permissions CREATE TABLE, VIEW, and CREATE PROCEDURES.

vCenter database administrator role:
SELECT, INSERT, DELETE, UPDATE, and EXECUTE.
EXECUTE permissions on sp_add_job, sp_delete_job, sp_add_jobstep, sp_update_job, sp_add_jobserver, sp_add_jobschedule, and sp_add_category stored procedures.
SELECT permission on syscategories, sysjobsteps, sysjobs_view, and sysjobs tables.

vCenter database user:
VIEW SERVER STATE and VIEW ANY DEFINITIONS.

Equivalent permissions must be set for Non-MS databases.

If the above database permissions are not set correctly, this is a finding.

For more information, refer to the following website: http://pubs.vmware.com/vsphere-60/index.jsp#com.vmware.vsphere.install.doc/GUID-36B92A8C-074A-4657-9938-62AB97225B91.html'
  desc 'fix', 'Configure correct permissions and roles for SQL:

Grant these privileges to a vCenter database administrator role used only for initial setup and periodic maintenance of the database:
Schema permissions ALTER, REFERENCES, and INSERT.
Permissions CREATE TABLE, VIEW, and CREATE PROCEDURES.

Grant these privileges to a vCenter database user role:
SELECT, INSERT, DELETE, UPDATE, and EXECUTE.
EXECUTE permissions on sp_add_job, sp_delete_job, sp_add_jobstep, sp_update_job, sp_add_jobserver, sp_add_jobschedule, and sp_add_category stored procedures.
SELECT permission on syscategories, sysjobsteps, sysjobs_view, and sysjobs tables.

Grant the permissions VIEW SERVER STATE and VIEW ANY DEFINITIONS to the vCenter database user.

For more information, refer to the following website: http://pubs.vmware.com/vsphere-60/index.jsp#com.vmware.vsphere.install.doc/GUID-36B92A8C-074A-4657-9938-62AB97225B91.html'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64759r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64007'
  tag rid: 'SV-78497r2_rule'
  tag stig_id: 'VCWN-06-000033'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69937r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
