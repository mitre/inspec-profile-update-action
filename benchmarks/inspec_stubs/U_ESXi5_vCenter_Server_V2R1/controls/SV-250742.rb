control 'SV-250742' do
  title 'A least-privileges assignment must be used for the vCenter Server database user.'
  desc 'Least-privileges mitigates attacks if the vCenter database account is compromised. vCenter requires very specific privileges on the database. Privileges normally required only for installation and upgrade must be removed for/during normal operation. These privileges may be reinstated if/when any future upgrade must be performed.'
  desc 'check', 'Verify only the runtime privileges needed for the current vCenter state, on either Oracle or Microsoft SQL Server, is assigned. 

Verify that the following permissions are granted to the vCenter user in the vCenter database.
GRANT ALTER ON SCHEMA :: <schema> to <user>;
GRANT REFERENCES ON SCHEMA :: <schema> to <user>;
GRANT INSERT ON SCHEMA :: <schema> to <user>;
GRANT CREATE TABLE to <user>;
GRANT CREATE VIEW to <user>;
GRANT CREATE Procedure to <user>;

For SQL, verify that the following permissions are granted to the user in the MSDB database. Note that the msdb database is used by SQL Server Agent for scheduling alerts and jobs.
GRANT SELECT on msdb.dbo.syscategories to <user>;
GRANT SELECT on msdb.dbo.sysjobsteps to <user>;
GRANT SELECT ON msdb.dbo.sysjobs to <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_job TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_delete_job TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_jobstep TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_update_job TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_category TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_jobserver TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_jobschedule TO <user>;

For Oracle, verify that the following permissions (or DBA role) are granted to the user.
grant connect to <user>
grant resource to <user>
grant create view to <user>
grant create materialized view to <user>
grant execute on dbms_job to <user>
grant execute on dbms_lock to <user>
grant unlimited tablespace to <user> 

If the runtime privileges are not configured per the above guidelines, this is a finding.'
  desc 'fix', 'Set the runtime privileges needed for the current vCenter state, on either Oracle or Microsoft SQL Server as noted below. 

Grant the following permissions to the vCenter user in the vCenter database:
GRANT ALTER ON SCHEMA :: <schema> to <user>;
GRANT REFERENCES ON SCHEMA :: <schema> to <user>;
GRANT INSERT ON SCHEMA :: <schema> to <user>;
GRANT CREATE TABLE to <user>;
GRANT CREATE VIEW to <user>;
GRANT CREATE Procedure to <user>;

Grant the following permissions to the user in the MSDB database. Note that the msdb database is used by SQL Server Agent for scheduling alerts and jobs.
GRANT SELECT on msdb.dbo.syscategories to <user>;
GRANT SELECT on msdb.dbo.sysjobsteps to <user>;
GRANT SELECT ON msdb.dbo.sysjobs to <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_job TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_delete_job TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_jobstep TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_update_job TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_category TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_jobserver TO <user>;
GRANT EXECUTE ON msdb.dbo.sp_add_jobschedule TO <user>;

For Oracle, either assign the DBA role or grant the following permissions to the user.
grant connect to <user>
grant resource to <user>
grant create view to <user>
grant create materialized view to <user>
grant execute on dbms_job to <user>
grant execute on dbms_lock to <user>
grant unlimited tablespace to <user>'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54177r799914_chk'
  tag severity: 'medium'
  tag gid: 'V-250742'
  tag rid: 'SV-250742r799916_rule'
  tag stig_id: 'VCENTER-000023'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54131r799915_fix'
  tag 'documentable'
  tag legacy: ['SV-51419', 'V-39561']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
