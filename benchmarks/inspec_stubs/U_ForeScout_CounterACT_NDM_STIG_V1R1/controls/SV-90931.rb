control 'SV-90931' do
  title 'CounterACT must restrict the ability to change the auditing to be performed within the system log based on selectable event criteria to the audit administrators role or to other roles or individuals.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, in near real time, within minutes, or within hours.

The individuals or roles to change the auditing are dependent on the security configuration of the network device. For example, it may be configured to allow only some administrators to change the auditing, while other administrators can review audit logs but not reconfigure auditing. Because this capability is so powerful, organizations should be extremely cautious about only granting this capability to fully authorized security personnel.'
  desc 'check', %q(Determine if CounterACT restricts the ability to change the auditing to be performed within the system log based on selectable event criteria to the audit administrator's role or to other roles or individuals.

This requirement may be verified by configuration review or demonstration.

1. Open the CounterACT Administrator Console and log on with admin or operator credentials. 
2. Select Tools >> Options >> Console User Profiles.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Edit".
4. Review the "Permissions" tab and verify the following "update" radio check boxes are enabled: Action Thresholds, CounterACT Appliance Configuration, and Enterprise Manager Control.

If CounterACT does not provide the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near real time, this is a finding.)
  desc 'fix', %q(Configure CounterACT to restrict the ability to change the auditing to be performed within the system log based on selectable event criteria to the audit administrator's role or to other roles or individuals.

Apply the following configuration changes:

1. Open the CounterACT Administrator Console and log on with admin or operator credentials.
2. Select Tools >> Options >> Console User Profiles.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Edit".
4. Review the "Permissions" tab and ensure the following "update" radio check boxes are enabled: Action Thresholds, CounterACT Appliance Configuration, and Enterprise Manager Control.)
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76243'
  tag rid: 'SV-90931r1_rule'
  tag stig_id: 'CACT-NM-000005'
  tag gtitle: 'SRG-APP-000353-NDM-000292'
  tag fix_id: 'F-82879r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
