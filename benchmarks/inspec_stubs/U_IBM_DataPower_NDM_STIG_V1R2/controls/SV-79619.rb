control 'SV-79619' do
  title 'The DataPower Gateway must generate an immediate alert for account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and ISSOs. Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes. 

In order to detect and respond to events that affect network administrator accessibility and device processing, network devices must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.'
  desc 'check', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. Verify that "Trap Event Subscriptions" include the Event Subscription codes that indicate account modification: 0x8240001c and 0x8240001f.

On the "Trap and Notification Targets" tab, verify that this configuration includes the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when account modification events occur.

On the Main tab, confirm that the "Administrative state" is set to "enabled". Additionally, confirm that that the run time state (shown at the top of the page after the text "SNMP Settings") indicates in brackets that the SNMP object is in an "up" state.

Confirm that when an account is modified, an appropriate 0x8240001c or 0x8240001f "Configuration settings applied" event appears in the DataPower audit log (In the WebGUI go to Status >> View Logs >> Audit Log), and that an appropriate notification is sent by the SNMP server specified on the "Trap and Notification Targets" tab of the DataPower SNMP Settings.

If this event message does not appear in the audit log, this is a finding.'
  desc 'fix', %q(In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. 

On the Trap Event Subscriptions tab, set to "on" the "Enable Default Event Subscriptions" option >> set to "warning" the "Minimum Priority" option >> configure "Trap Event Subscriptions" to include an Event Subscription that indicates account creation by adding 0x8240001c and 0x8240001f Event Subscriptions.

Example log result: "[conf][success][0x8240001c] (admin:default:web-gui:192.168.65.1): user 'TestUser' Configuration settings applied"

On the "Trap and Notification Targets" tab, add the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when accounts are modified.

On the Main tab, set the "Administrative state" to "enabled" >> Click "Save Configuration".)
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65129'
  tag rid: 'SV-79619r1_rule'
  tag stig_id: 'WSDP-NM-000086'
  tag gtitle: 'SRG-APP-000320-NDM-000284'
  tag fix_id: 'F-71069r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
