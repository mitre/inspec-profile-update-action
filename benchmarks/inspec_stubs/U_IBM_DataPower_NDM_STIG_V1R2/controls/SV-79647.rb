control 'SV-79647' do
  title 'The DataPower Gateway must implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner.'
  desc 'Unauthorized changes to the baseline configuration could make the device vulnerable to various attacks or allow unauthorized access to the device. Changes to device configurations can have unintended side effects, some of which may be relevant to security. 

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the device. Examples of security responses include, but are not limited to the following: halting application processing; halting selected functions; or issuing alerts/notifications to organizational personnel when there is an unauthorized modification of a configuration item. The appropriate automated security response may vary depending on the nature of the baseline configuration change, the role of the network device, the availability of organizational personnel to respond to alerts, etc.'
  desc 'check', 'This requirement may be verified by executing each configuration item modification event that requires tracking and then examining the audit log (the most recent entry will be at the bottom of the log).

Using the DataPower Gateway web interface, the audit log event code for each configuration item modification event shown in the audit log must be confirmed to exist in the list of Trap Event Subscriptions in the SNMP notification settings: Administration >> Access >> SNMP Settings, Trap Event Subscriptions tab.

If the code is not present, this is a finding.'
  desc 'fix', 'Configure the DataPower Gateway to use an SNMP trap to send the log failure event to a properly configured SNMP server.

In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. Configure "Trap Event Subscriptions" to include Event Subscriptions that indicate unauthorized configuration changes. Configure "Trap and Notification Targets" to include an approved SNMP server that generates alerts that will be forwarded to organizational personnel when a modification to a configuration item has occurred.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65157'
  tag rid: 'SV-79647r1_rule'
  tag stig_id: 'WSDP-NM-000105'
  tag gtitle: 'SRG-APP-000379-NDM-000303'
  tag fix_id: 'F-71097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
