control 'SV-75319' do
  title 'The Arista Multilayer Switch must activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.'
  desc "Predictable failure prevention requires organizational planning to address device failure issues. If components key to maintaining the device's security fail to function, the device could continue operating in an insecure state. If appropriate actions are not taken when a network device failure occurs, a denial of service condition may occur that could result in mission failure since the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the network device must activate a system alert message, send an alarm, or shut down."
  desc 'check', 'Determine if the network device activates a system alert message, sends an alarm, and/or automatically shuts down when a component failure is detected. This requirement may be verified by demonstration or configuration review. 

If the network device does not activate a system alert message, send an alarm, or automatically shut down when a component failure is detected, this is a finding.

This is a function of SNMP Traps. Verify the SNMP configuration is present in the output of the "show running-config" command and that SNMP is active via the "show snmp" command.'
  desc 'fix', 'Configure the network device to activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.

SNMP is used to fulfill this function. An example SNMP configuration is provided below. To configure SNMP according to site-specific policies and procedures, refer to the Arista Configuration Guide, Chapter 37.

snmp-server engineID local 
snmp-server view snmpview system included
snmp-server group ROgroup v3 priv read snmpview
snmp-server group RWgroup v3 priv write snmpview
snmp-server user disa ROgroup v3
snmp-server user disaRW RWgroup v3
snmp-server host 10.1.1.1 version 3 priv disaRW
snmp-server host 10.2.2.2 version 3 noauth disaRW
snmp-server host 10.3.3.3 version 3 noauth disaRW
snmp-server host 127.0.0.1 version 3 noauth auth
snmp-server host 172.22.29.82 version 3 noauth disaRW
snmp-server enable traps'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60861'
  tag rid: 'SV-75319r1_rule'
  tag stig_id: 'AMLS-NM-000260'
  tag gtitle: 'SRG-APP-000268-NDM-000274'
  tag fix_id: 'F-66573r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end
