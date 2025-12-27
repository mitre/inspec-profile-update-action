control 'SV-98921' do
  title 'In the event of a system failure, the vROps PostgreSQL DB must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes. 

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT name, setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');"

If "fsync", "full_page_writes", and "synchronous_commit" are not set to "on", this is a finding.

The command should return the below lines:
          name                       | setting
---------------------------+---------
 fsync                                  | on
 full_page_writes          | on
 synchronous_commit | on
(3 rows))
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET <name> TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();"

Note: Substitute <name> with the incorrectly set parameter.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88271'
  tag rid: 'SV-98921r1_rule'
  tag stig_id: 'VROM-PG-000255'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-95013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
