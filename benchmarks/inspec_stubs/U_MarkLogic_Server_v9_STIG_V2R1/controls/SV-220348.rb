control 'SV-220348' do
  title 'MarkLogic Server must shut down by default upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When the need for system availability does not outweigh the need for a complete audit trail, the DBMS should shut down immediately, rolling back all in-flight transactions.

Systems in which audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. Sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', 'If the application owner has determined the need for system availability outweighs the need for a complete audit trail, this is not applicable.

If the system is configured for High Availability (HA), and the application owner has determined the need for a complete audit trail outweighs the need for system availability, this is a finding.

The following are the minimum configuration requirements for HA:
- Failover enabled = True for the Group
- Security database forests are configured with replica forests
- Databases associated with the users application are configured with replica forests

If HA is a requirement for Administrative functions:
- App Services database forests are configured with replica forests
- Modules database forests are configured with replica forests 
- Documents database forests are configured with replica forests
- Triggers database forests are configured with replica forests

Perform the check for HA from the MarkLogic Admin Interface with a user that holds administrative-level privileges: 

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. On the Configuration tab, check the value of "failover enabled".
True = HA can be enabled
False = HA cannot be enabled
4. Click the Databases icon in the left tree menu.
5. Click the Security Database.
6. Click the Status Tab.
7. Review the Forest section:
a. Count the number of forests with a state of "open".
b. Count the number of forests with a state of "[sync|async|wait] replicating".
c. The number of replicating forests should be greater than or equal to the number of open forests.
8. Repeat steps 4-7 for the user application databases (data/content, modules, triggers, etc.).
9. Repeat steps 4-7 for the following databases if HA is required for Administrative functions:
- App Services
- Modules
- Documents
- Triggers'
  desc 'fix', 'Configure the database to go offline, rolling back all in-flight transactions, in the case of an auditing failure due to insufficient disk space.

Perform the fix from the MarkLogic Admin Interface with a user that holds administrative-level privileges: 

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. On the Configuration tab set the value of "failover enabled" to "false".
4. Click OK to save the configuration.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22063r401495_chk'
  tag severity: 'medium'
  tag gid: 'V-220348'
  tag rid: 'SV-220348r622777_rule'
  tag stig_id: 'ML09-00-001600'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag fix_id: 'F-22052r401496_fix'
  tag 'documentable'
  tag legacy: ['SV-110043', 'V-100939']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
