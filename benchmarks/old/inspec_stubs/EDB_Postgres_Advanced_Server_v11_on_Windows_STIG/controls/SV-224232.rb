control 'SV-224232' do
  title 'The EDB Postgres Advanced Server must generate audit records when successful/unsuccessful logons, connections, or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to the DBMS.

It is also necessary to track failed attempts to log on to the DBMS. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.

'
  desc 'check', 'Execute the following SQL as enterprisedb:

 SHOW edb_audit_connect;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:

 ALTER SYSTEM SET edb_audit_connect = 'all';
 SELECT pg_reload_conf();

or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25905r495713_chk'
  tag severity: 'medium'
  tag gid: 'V-224232'
  tag rid: 'SV-224232r508023_rule'
  tag stig_id: 'EP11-00-011800'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-25893r495714_fix'
  tag satisfies: ['SRG-APP-000503-DB-000350', 'SRG-APP-000503-DB-000351']
  tag 'documentable'
  tag legacy: ['SV-109589', 'V-100485']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
