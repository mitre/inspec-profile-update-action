control 'SV-219826' do
  title 'Fixed user and public database links must be authorized for use.'
  desc 'Database links define connections that may be used by the local database to access remote Oracle databases. These links provide a means for a compromise to the local database to spread to remote databases in the distributed database environment. Limiting or eliminating use of database links where they are not required to support the operational system can help isolate compromises to the local or a limited number of databases.'
  desc 'check', "From SQL*Plus:

select owner||': '||db_link from dba_db_links;

If no records are returned from the first SQL statement, this check is not a finding.

Confirm the public and fixed user database links listed are documented in the System Security Plan, are authorized by the ISSO, and are used for replication or operational system requirements.

If any are not, this is a finding."
  desc 'fix', 'Document all authorized connections from the database to remote databases in the System Security Plan.

Remove all unauthorized remote database connection definitions from the database.

From SQL*Plus:

  drop database link [link name];
OR
  drop public database link [link name];

Review remote database connection definitions periodically and confirm their use is still required and authorized.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21537r533017_chk'
  tag severity: 'medium'
  tag gid: 'V-219826'
  tag rid: 'SV-219826r879887_rule'
  tag stig_id: 'O121-BP-021400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21536r533018_fix'
  tag 'documentable'
  tag legacy: ['SV-75905', 'V-61415']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
