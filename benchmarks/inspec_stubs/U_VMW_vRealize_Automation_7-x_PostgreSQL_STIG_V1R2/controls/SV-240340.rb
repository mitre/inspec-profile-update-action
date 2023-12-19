control 'SV-240340' do
  title 'vRA Postgres must be configured to use the correct port.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*port\b' /storage/db/pgdata/postgresql.conf

If the port is set to "5432", this is NOT a finding.

If the port is not set to "5432" and if the ISSO does not have documentation of an approved variance for using a non-standard port, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET port TO '5432';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43573r668886_chk'
  tag severity: 'medium'
  tag gid: 'V-240340'
  tag rid: 'SV-240340r879588_rule'
  tag stig_id: 'VRAU-PG-000560'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-43532r668863_fix'
  tag 'documentable'
  tag legacy: ['SV-100107', 'V-89457']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
