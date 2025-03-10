control 'SV-79637' do
  title 'The DataPower Gateway must generate an immediate real-time alert of all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. Verify that "Trap Event Subscriptions" include Event Subscription codes that indicate audit failure: 0x80c0006a, 0x82400067, 0x00330034, and 0x80400080.

On the "Trap and Notification Targets" tab, verify that this configuration includes the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when audit failure events occur.

On the Main tab, confirm that the "Administrative state" is set to "enabled". Additionally, confirm that that the run time state (shown at the top of the page after the text "SNMP Settings") indicates in brackets that the SNMP object is in an "up" state.

If the SNMP object state is down, this is a finding.'
  desc 'fix', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. On the Trap Event Subscriptions tab, set to "on" the "Enable Default Event Subscriptions" option >> Set to "warning" the "Minimum Priority" option >> Configure "Trap Event Subscriptions" to include Event Subscriptions that indicate audit log failure: add 0x80c0006a, 0x82400067, 0x00330034, and 0x80400080.

On the "Trap and Notification Targets" tab, add the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when audit failure events occur.

On the Main tab, set the "Administrative state" to "enabled" >> Click "Save Configuration".'
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65775r1_chk'
  tag severity: 'low'
  tag gid: 'V-65147'
  tag rid: 'SV-79637r1_rule'
  tag stig_id: 'WSDP-NM-000097'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-71087r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
