control 'SV-79631' do
  title 'The DataPower Gateway must provide the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near-real-time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near-real-time, within minutes, or within hours.

The individuals or roles to change the auditing are dependent on the security configuration of the network device--for example, it may be configured to allow only some administrators to change the auditing, while other administrators can review audit logs but not reconfigure auditing. Because this capability is so powerful, organizations should be extremely cautious about only granting this capability to fully authorized security personnel.'
  desc 'check', 'View the following three auditing configuration capabilities:

Verify existing log targets and Event Subscriptions. Using the web interface, go to Objects >> Logging Configuration >> Log Target. View the Event Subscriptions tab to audit log subscription Event Priority levels.

SNMP Settings. Using the web interface, go to Administration >> Access >> SNMP Settings, Trap Event Subscriptions tab. View the Event Subscriptions tab to verify audit log subscription Event Priority levels.

Audit log settings. Using the web interface, go to Object >> Logging Configuration >> Audit Log Settings. Verify that the Audit Level is set at the full. If it is not, this is a finding.'
  desc 'fix', 'Configure the following near real-time auditing capabilities: 

1. Subscriptions to the DataPower audit logs and associated event categories and Minimum Event Priority.

Set log targets and Event Subscription. Using the web interface, go to Objects >> Logging Configuration >> Log Target. Add an audit log target. View the Event Subscriptions tab to set audit log subscription Event Priority level.

2. SNMP trap event subscriptions to audit log events

SNMP Settings. Using the web interface, go to Administration >> Access >> SNMP Settings, Trap Event Subscriptions tab. Add audit log event codes to the SNMP notification configuration. 

3. Audit levels.

Using the web interface, go to Object >> Logging Configuration >> Audit Log Settings. Set the Audit Levels at the desired level (standard or full).'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65141'
  tag rid: 'SV-79631r1_rule'
  tag stig_id: 'WSDP-NM-000094'
  tag gtitle: 'SRG-APP-000353-NDM-000292'
  tag fix_id: 'F-71081r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
