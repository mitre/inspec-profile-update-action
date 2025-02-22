control 'SV-239773' do
  title 'The vROps PostgreSQL DB must provide audit record generation for DoD-defined auditable events within all DBMS/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_line_prefix\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_line_prefix is not set to "%m %d %u %r %p %l %c", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# sed -i.bak "/log_line_prefix.*/ d" /storage/db/vcops/vpostgres/data/postgresql.conf
# sed -i "$ a log_line_prefix = '%m %d %u %r %p %l %c'" /storage/db/vcops/vpostgres/data/postgresql.conf
# su postgres
postgres@vRealizeClusterNode:> cd /opt/vmware/vpostgres/current
postgres@vRealizeClusterNode:> /opt/vmware/vpostgres/9.3/bin/pg_ctl restart -D /storage/db/vcops/vpostgres/data
postgres@vRealizeClusterNode:> exit)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43006r663694_chk'
  tag severity: 'medium'
  tag gid: 'V-239773'
  tag rid: 'SV-239773r879559_rule'
  tag stig_id: 'VROM-PG-000025'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-42965r663695_fix'
  tag 'documentable'
  tag legacy: ['SV-98867', 'V-88217']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
