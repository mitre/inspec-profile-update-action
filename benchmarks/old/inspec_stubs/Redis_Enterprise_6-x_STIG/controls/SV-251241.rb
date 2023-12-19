control 'SV-251241' do
  title 'In the event of a system failure, Redis Enterprise DBMS must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes.

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.

Additional information can be found at:
https://docs.redislabs.com/latest/rs/administering/troubleshooting/cluster-recovery/'
  desc 'check', 'In the Redis Enterprise web UI, select settings and then alerts.

Verify the alerts documented by the ISSO/ISSM  are checked.

If required alerts are not checked, this is a finding.

In the Redis Enterprise web UI, select databases, then select the individual databases.

For each database, select configuration.

Verify that "Persistence", "Periodic backup", and "Alerts" are all configured as organizationally defined and documented by the ISSO or ISSM. 

Verify that organizationally defined path for the centralized log server is also applied and configured external to the database.

If any of these items are not configured as documented, this is a finding.'
  desc 'fix', 'In the Redis Enterprise web UI, select databases and then select the individual databases.

For each database, select configuration.

Check the box and configure the following as defined by the ISSO/ISSM: "Persistence", "Periodic backup", and "Alerts" 

Ensure that organizationally defined path for the centralized log server is also applied and configured external to the database.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54676r804911_chk'
  tag severity: 'medium'
  tag gid: 'V-251241'
  tag rid: 'SV-251241r804913_rule'
  tag stig_id: 'RD6X-00-010700'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-54630r804912_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
