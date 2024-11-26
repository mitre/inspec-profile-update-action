control 'SV-79607' do
  title 'The DataPower Gateway must generate alerts that can be forwarded to the administrators and ISSO when accounts are disabled.'
  desc 'When application accounts are disabled, administrator accessibility is affected. Accounts are utilized for identifying individual device administrators or for identifying the device processes themselves. 

In order to detect and respond to events that affect administrator accessibility and device processing, devices must audit account disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that device accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.'
  desc 'check', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. Verify that "Trap Event Subscriptions" include the Event Subscription codes that indicate an account is disabled: 0x8240001c and 0x8240001f.

On the "Trap and Notification Targets" tab, verify that this configuration includes the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when account disabled events occur.

On the Main tab, confirm that the "Administrative state" is set to "enabled". Additionally, confirm that that the run time state (shown at the top of the page after the text "SNMP Settings") indicates in brackets that the SNMP object is in an "up" state.

Confirm that when an account is disabled, an appropriate 0x8240001c or 0x8240001f "disabled" event appears in the DataPower audit log (In the WebGUI go to Status >> View Logs >> Audit Log), and that an appropriate notification is sent by the SNMP server specified on the "Trap and Notification Targets" tab of the DataPower SNMP Settings.

If this event message does not appear in the audit log, this is a finding.'
  desc 'fix', %q(In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. 

On the Trap Event Subscriptions tab, set to "on" the "Enable Default Event Subscriptions" option >> set to "warning" the "Minimum Priority" option >> configure "Trap Event Subscriptions" to include an Event Subscription that indicates account is disabled by adding 0x8240001c and 0x8240001f Event Subscriptions.

Example log result: "[conf][success][0x8240001c] (dp-technician:default:system:*): web-mgmt 'WebGUI-Settings' - admin-state disabled."

On the "Trap and Notification Targets" tab, add the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when accounts are disabled.

On the Main tab, set the "Administrative state" to "enabled" >> Click "Save Configuration".)
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65117'
  tag rid: 'SV-79607r1_rule'
  tag stig_id: 'WSDP-NM-000079'
  tag gtitle: 'SRG-APP-000293-NDM-000277'
  tag fix_id: 'F-71057r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
