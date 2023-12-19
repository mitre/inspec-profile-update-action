control 'SV-75317' do
  title 'The Arista Multilayer Switch must reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives."
  desc 'check', 'Determine if the network device is configured to reveal error messages only to authorized individuals. This requirement may be verified by demonstration or configuration review. This requirement can be met by a central audit server if the network device is configured to send audit logs to that audit server.

If the network device reveals error messages to any unauthorized individuals, this is a finding.

This is a function of SNMP Traps. Verify the SNMP configuration is present in the output of the "show running-config" command and that SNMP is active via the "show snmp" command.'
  desc 'fix', 'Configure the network device or its associated audit server to reveal error messages only to authorized individuals.

SNMP is used to fulfill this function. An example SNMP configuration is provided below. To configure SNMP according to site-specific policies and procedures, refer to the Arista Configuration Guide Chapter 37

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
  tag check_id: 'C-61807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60859'
  tag rid: 'SV-75317r1_rule'
  tag stig_id: 'AMLS-NM-000250'
  tag gtitle: 'SRG-APP-000267-NDM-000273'
  tag fix_id: 'F-66571r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
