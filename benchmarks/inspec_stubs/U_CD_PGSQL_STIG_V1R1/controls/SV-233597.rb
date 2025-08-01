control 'SV-233597' do
  title 'PostgreSQL must enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'To list all the permissions of individual roles, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "\\du

If any role has SUPERUSER that should not, this is a finding.

Next, list all the permissions of databases and schemas by running the following SQL:

$ sudo su - postgres
$ psql -c "\\l"
$ psql -c "\\dn+"

If any database or schema has update ("W") or create ("C") privileges and should not, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).

Use ALTER ROLE to remove accesses from roles:

$ psql -c "ALTER ROLE <role_name> NOSUPERUSER"

Use REVOKE to remove privileges from databases and schemas:

$ psql -c "REVOKE ALL PRIVILEGES ON <table> FROM <role_name>"'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36791r607014_chk'
  tag severity: 'medium'
  tag gid: 'V-233597'
  tag rid: 'SV-233597r617333_rule'
  tag stig_id: 'CD12-00-009600'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-36756r607015_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
