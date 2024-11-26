control 'SV-251616' do
  title 'IDMS executing in a local mode batch environment must be able to manually recover or restore database areas affected by failed transactions.'
  desc 'Local mode update jobs can either use local mode journaling or perform a backup of the database prior to executing the local mode updates.

Local mode journaling could be completed if the database is too large to back up in a reasonable amount of time. To use local mode journals for manual recovery, the journals must be defined in the IDMS DMCL as a TAPE JOURNAL and a DD for the journal file must be coded in the update job step JCL. The local mode update job must include the IDMS DMCL name in the SYSIDMS  parameter file as DMCL=dmcl-name. If the local mode update step fails, then a rollback step must be performed to recover the database.

Without local mode journaling, the local mode batch job should include a backup of the database step, a local mode update step and  another backup of the database step if the local updates step successfully complete. If the local mode update step fails, then a step to restore the database from the first backup step must be performed.

'
  desc 'check', 'Check that the job or prior job contains a step to vary the areas offline to the CV and takes a backup. If not there, it is a finding.

Perform a second check to verify there is a restore step or JCL that can be used when the job fails.'
  desc 'fix', 'Add a backup step/job if needed and create a restore step/job if needed.'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55051r807713_chk'
  tag severity: 'low'
  tag gid: 'V-251616'
  tag rid: 'SV-251616r807715_rule'
  tag stig_id: 'IDMS-DB-000440'
  tag gtitle: 'SRG-APP-000225-DB-000153'
  tag fix_id: 'F-55005r807714_fix'
  tag satisfies: ['SRG-APP-000225-DB-000153', 'SRG-APP-000226-DB-000147']
  tag 'documentable'
  tag cci: ['CCI-001190', 'CCI-001665']
  tag nist: ['SC-24', 'SC-24']
end
