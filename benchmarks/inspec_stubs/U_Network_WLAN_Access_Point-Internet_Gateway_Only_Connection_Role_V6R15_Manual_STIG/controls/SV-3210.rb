control 'SV-3210' do
  title 'The network device must not use the default or well-known SNMP community strings public and private.'
  desc 'Network devices may be distributed by the vendor pre-configured with an SNMP agent using the well-known SNMP community strings public for read only and private for read and write authorization. An attacker can obtain information about a network device using the read community string "public". In addition, an attacker can change a system configuration using the write community string "private".'
  desc 'check', 'Review the network devices configuration and verify if either of the SNMP community strings "public" or "private" is being used.

If default or well-known community strings are used for SNMP, this is a finding.'
  desc 'fix', 'Configure unique SNMP community strings replacing the default community strings.'
  impact 0.7
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-3822r7_chk'
  tag severity: 'high'
  tag gid: 'V-3210'
  tag rid: 'SV-3210r4_rule'
  tag stig_id: 'NET1665'
  tag gtitle: 'Using default SNMP community names.'
  tag fix_id: 'F-3235r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
