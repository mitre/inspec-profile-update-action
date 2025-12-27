control 'SV-239208' do
  title 'VMware Postgres must write log entries to disk prior to returning operation success or failure.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes. 

Because it is usually not possible to test this capability in a production environment, systems should be validated either in a testing environment or prior to installation. This is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');"|sed -n '3,5p'|sed -e 's/^[ ]*//'

Expected result:

fsync              | on
full_page_writes   | on
synchronous_commit | on

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET <name> TO 'on';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();"

Note: Substitute <name> with the incorrectly set parameter (fsync, full_page_writes, synchronous_commit))
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42441r678995_chk'
  tag severity: 'medium'
  tag gid: 'V-239208'
  tag rid: 'SV-239208r678997_rule'
  tag stig_id: 'VCPG-67-000016'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-42400r678996_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
