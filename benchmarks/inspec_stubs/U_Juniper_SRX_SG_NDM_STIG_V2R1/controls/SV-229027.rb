control 'SV-229027' do
  title 'The Juniper SRX Services Gateway must detect the addition of components and issue a priority 1 alert to the ISSM and SA, at a minimum.'
  desc 'The network device must automatically detect the installation of unauthorized software or hardware onto the device itself. Monitoring may be accomplished on an ongoing basis or by periodic monitoring. Automated mechanisms can be implemented within the network device and/or in another separate information system or device. If the addition of unauthorized components or devices is not automatically detected, then such components or devices could be used for malicious purposes, such as transferring sensitive data to removable media for compromise.

Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system).'
  desc 'check', 'Verify SNMP is configured to capture chassis and device traps. If Syslog or a console method is used, verify that method instead.

[edit]
show snmp v3
 
If an immediate alert is not sent via SNMPv3 or another method, this is a finding.'
  desc 'fix', 'Update the SNMP configuration with the following device trap settings. This is an example method. Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). 

set snmp v3 notify-filter device-traps oid jnxChassisTraps include
set snmp v3 notify-filter device-traps oid jnxChassisOKTraps include
set snmp v3 notify-filter device-traps oid system include
set snmp v3 notify-filter device-traps oid .1 include
set snmp v3 notify-filter device-traps oid'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-31342r518257_chk'
  tag severity: 'low'
  tag gid: 'V-229027'
  tag rid: 'SV-229027r518259_rule'
  tag stig_id: 'JUSX-DM-000099'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31319r518258_fix'
  tag 'documentable'
  tag legacy: ['SV-81089', 'V-66599']
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
