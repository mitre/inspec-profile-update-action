control 'SV-258587' do
  title 'The ICS must be configured to generate log records containing sufficient information about where, when, identity, source, or outcome of the events.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

VPN gateways often have a separate audit log for capturing VPN status and other information about the traffic (as opposed to the log capturing administrative and configuration actions).

Associating event types with detected events in the network audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured VPN gateway.

'
  desc 'check', 'In the ICS Web UI, navigate to System >> Log/Monitoring >> User Access >> Settings.

Under "Select Events to Log", verify all items are checked.

If the ICS must be configured to generate log records containing information investigate the events, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Log/Monitoring >> User Access >> Settings.
1. Under "Select Events to Log", check all items.
2. Set the standard filer.
3. Click "Add".
4. Click "Save Changes".

Note: If the site uses SNMP, the configuration can be used in conjunction with this requirement which is recommended. By default, SNMP is disabled. The device only supports Simple Network Management Protocol version 3 (SNMPv3) in a DOD configuration. The device supports queries only, traps only, or both when enabling SNMP. Refer to SRG-NET-000335-VPN-001270 for configuration.'
  impact 0.3
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62327r930447_chk'
  tag severity: 'low'
  tag gid: 'V-258587'
  tag rid: 'SV-258587r930449_rule'
  tag stig_id: 'IVCS-VN-000090'
  tag gtitle: 'SRG-NET-000078-VPN-000290'
  tag fix_id: 'F-62236r930448_fix'
  tag satisfies: ['SRG-NET-000078-VPN-000290', 'SRG-NET-000079-VPN-000300', 'SRG-NET-000088-VPN-000310', 'SRG-NET-000089-VPN-000330', 'SRG-NET-000091-VPN-000350', 'SRG-NET-000077-VPN-000280', 'SRG-NET-000313-VPN-001050', 'SRG-NET-000492-VPN-001980']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000172', 'CCI-001487', 'CCI-002314']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 c', 'AU-3 f', 'AC-17 (1)']
end
