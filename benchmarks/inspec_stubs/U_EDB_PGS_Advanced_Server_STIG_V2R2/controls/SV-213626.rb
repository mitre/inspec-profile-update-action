control 'SV-213626' do
  title 'The EDB Postgres Advanced Server must enforce access restrictions associated with changes to the configuration of the EDB Postgres Advanced Server or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review the security configuration of the EDB Postgres database(s). 

If unauthorized users can start the SQL Server Configuration Manager or SQL Server Management Studio, this is a finding. 

If EDB Postgres does not enforce access restrictions associated with changes to the configuration of the database(s), this is a finding. 

- - - - - 

To assist in conducting reviews of permissions, the following psql commands describe permissions of databases, schemas, and users: 

\\l
\\dn+
\\du

Permissions of concern in this respect include the following, and possibly others: 

- any user with SUPERUSER privileges 
- any database or schema with "C" (create) or "w" (update) privileges that are not necessary'
  desc 'fix', 'Configure EDB PPAS to enforce access restrictions associated with changes to the configuration of the EDB Postgres database(s).'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14848r290190_chk'
  tag severity: 'medium'
  tag gid: 'V-213626'
  tag rid: 'SV-213626r508024_rule'
  tag stig_id: 'PPS9-00-008500'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-14846r290191_fix'
  tag 'documentable'
  tag legacy: ['SV-83609', 'V-69005']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
