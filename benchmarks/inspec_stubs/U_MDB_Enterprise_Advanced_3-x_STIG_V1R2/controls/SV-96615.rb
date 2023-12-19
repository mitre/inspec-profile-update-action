control 'SV-96615' do
  title 'MongoDB must provide the means for individuals in authorized roles to change the auditing to be performed on all application components, based on all selectable event criteria within organization-defined time thresholds.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near real time, within minutes, or within hours.'
  desc 'check', 'The MongoDB auditing facility allows authorized administrators and users track system activity. Once auditing is configured and enabled, changes to the audit events and filters require restarting the mongod (and mongos, if applicable) instances. This can be done with zero down time by performing the modifications using a rolling maintenance approach (i.e., change the parameters on the secondaries, step down the primary such that one of the reconfigured secondaries becomes the primary then reconfigure the old primary). 

If replica sets or the rolling maintenance approach is not used for the procedure by the application owner, this is a finding.'
  desc 'fix', 'Use the rolling maintenance procedure.

For each member of a replica set, starting with a secondary member, perform the following sequence of events, ending with the primary:

1. Restart the mongod instance as a standalone.
2. Perform the configure auditing task on the standalone instance.
3. Restart the mongod instance as a member of the replica set.'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81901'
  tag rid: 'SV-96615r1_rule'
  tag stig_id: 'MD3X-00-000590'
  tag gtitle: 'SRG-APP-000353-DB-000324'
  tag fix_id: 'F-88751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
