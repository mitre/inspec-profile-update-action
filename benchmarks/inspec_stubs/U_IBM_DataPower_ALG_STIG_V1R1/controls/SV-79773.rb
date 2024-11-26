control 'SV-79773' do
  title 'The DataPower Gateway providing content filtering must be configured to integrate with a system-wide intrusion detection system.'
  desc 'Without coordinated reporting between separate devices, it is not possible to identify the true scale and possible target of an attack.

Integration of the ALG with a system-wide intrusion detection system supports continuous monitoring and incident response programs. This requirement applies to monitoring at internal boundaries using TLS gateways, web content filters, email gateways, and other types of ALGs.

ALGs can work as part of the network monitoring capabilities to off-load inspection functions from the external boundary IDPS by performing more granular content inspection of protocols at the upper layers of the OSI reference model.'
  desc 'check', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. 

Verify that Trap Event Subscriptions are associated with intrusion detection. Verify that Trap and Notification Targets includes an approved SNMP server that generates alerts that will be forwarded to the system-wide intrusion detection system.

If no trap event subscriptions are configured on no SNMP server configured as a target, this is a finding.'
  desc 'fix', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings.

Configure the "Trap Event Subscriptions" tab to include desired event codes. Set the Notification Targets tab to include an approved SNMP server that generates alerts that will be forwarded to the system-wide intrusion detection system.'
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65911r1_chk'
  tag severity: 'low'
  tag gid: 'V-65283'
  tag rid: 'SV-79773r1_rule'
  tag stig_id: 'WSDP-AG-000107'
  tag gtitle: 'SRG-NET-000383-ALG-000135'
  tag fix_id: 'F-71223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
