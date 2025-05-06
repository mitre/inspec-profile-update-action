control 'SV-213656' do
  title 'The EDB Postgres Advanced Server must generate audit records when unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to the DBMS. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.'
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW edb_audit_connect;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:

ALTER SYSTEM SET edb_audit_connect = 'all';
ALTER SYSTEM SET edb_audit_disconnect = 'all';
SELECT pg_reload_conf();   

or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14878r290280_chk'
  tag severity: 'medium'
  tag gid: 'V-213656'
  tag rid: 'SV-213656r508024_rule'
  tag stig_id: 'PPS9-00-011900'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-14876r290281_fix'
  tag 'documentable'
  tag legacy: ['V-69061', 'SV-83665']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
