control 'SV-98909' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT datname FROM pg_database WHERE datistemplate = false;"

If the output is not the following lines, this is a finding:
 datname
----------
 postgres
 VCDB
(2 rows)'
  desc 'fix', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "DROP DATABASE IF EXISTS <name>;"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88259'
  tag rid: 'SV-98909r1_rule'
  tag stig_id: 'VROM-PG-000160'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-95001r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
