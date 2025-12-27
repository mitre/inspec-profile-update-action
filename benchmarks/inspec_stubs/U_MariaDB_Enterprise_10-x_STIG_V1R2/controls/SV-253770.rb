control 'SV-253770' do
  title 'MariaDB must be able to generate audit records when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

Default Audit Filter is applied to all users by default. 

Named Audit Filters are assigned to specific users. 

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Check what Named Audit Filters are assigned to what users: 

MariaDB> SELECT sau.host, sau.user, saf.filtername,
   JSON_DETAILED(saf.rule)
FROM mysql.server_audit_filters saf
JOIN mysql.server_audit_users sau
   ON saf.filtername = sau.filtername
WHERE saf.filtername != 'default'\\G

If the MariaDB Enterprise Audit plugin is not active and/or necessary auditing is not in place, this is a finding."
  desc 'fix', %q(If the MariaDB Enterprise Audit plugin is not active, enable it in one of the two following ways. 

1. Config file (requires restart): 

[mariadb]
server_audit_logging = ON

2. SQL (does not require restart): 

MariaDB> SET GLOBAL server_audit_logging=ON;

Once the MariaDB Enterprise Audit plugin is loaded, verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the necessary auditing is not in place for all or specific users, modify the filters. 

To modify the default filter, delete, and recreate: 

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "logging":"ON",
            "connect_event":"ALL",
            "query_event":"ALL",
            "table_event":"ALL"
         }'
      ));

Specific objects can be added to filters with inclusion or exclusion. 

ignore_databases: Do not log actions on these databases. 
ignore_tables: Do not log actions on these tables. 
databases: Log actions on these databases.
tables: Log actions on these tables.

Example: 

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES (
       'reporting',
       JSON_COMPACT(
          '{
              "tables": [
                  "production.*",
                  "reporting.*",
                  {
                     "table_event": [
                         "WRITE",
                         "CREATE",
                         "DROP",
                         "RENAME",
                         "ALTER"
                     ],
                     "query_event": [
                         "DML",
                         "DDL",
                         {
                             "ignore_tables": [
                                 "production.customer_profiles",
                                 "production.customer_addresses"
                             ]
                         }
                     ]
                  }
              ]
          }'
       )
    );)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57222r841833_chk'
  tag severity: 'medium'
  tag gid: 'V-253770'
  tag rid: 'SV-253770r841835_rule'
  tag stig_id: 'MADB-10-011800'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag fix_id: 'F-57173r841834_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
