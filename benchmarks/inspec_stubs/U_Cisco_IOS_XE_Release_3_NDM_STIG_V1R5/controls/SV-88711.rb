control 'SV-88711' do
  title 'The Cisco IOS XE router must provide the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near-real-time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near-real-time, within minutes, or within hours.

The individuals or roles to change the auditing are dependent on the security configuration of the network device--for example, it may be configured to allow only some administrators to change the auditing, while other administrators can review audit logs but not reconfigure auditing. Because this capability is so powerful, organizations should be extremely cautious about only granting this capability to fully authorized security personnel.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to only allow individuals in the proper role to select audited events.

The configuration should look similar to the example below:

parser view Senior-Admin
 secret 5 $1$hW3m$PE.3zCJYeSrvYflFey71R.
 commands exec include all configure
 commands exec include all show

parser view Auditor
 secret 5 $1$qb3F$SrdJW2oyyDzq1L94I7eED.
 commands exec include show logging

If this is not configured to only allow individuals in the proper role to select audited events, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router using the following commands:

parser view Senior-Admin
 secret 5 $1$hW3m$PE.3zCJYeSrvYflFey71R.
 commands exec include all configure
 commands exec include all show

parser view Auditor
 secret 5 $1$qb3F$SrdJW2oyyDzq1L94I7eED.
 commands exec include show logging'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74127r4_chk'
  tag severity: 'low'
  tag gid: 'V-74037'
  tag rid: 'SV-88711r2_rule'
  tag stig_id: 'CISR-ND-000096'
  tag gtitle: 'SRG-APP-000353-NDM-000292'
  tag fix_id: 'F-80579r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
