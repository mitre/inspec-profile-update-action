control 'SV-209043' do
  title 'The snmpd service must not use a default password.'
  desc 'Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system.'
  desc 'check', 'To ensure the default password is not set, run the following command: 

# grep -v "^#" /etc/snmp/snmpd.conf| grep public

There should be no output. 
If there is output, this is a finding.'
  desc 'fix', 'Edit "/etc/snmp/snmpd.conf", remove default community string "public". Upon doing that, restart the SNMP service: 

# service snmpd restart'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9296r357914_chk'
  tag severity: 'high'
  tag gid: 'V-209043'
  tag rid: 'SV-209043r603263_rule'
  tag stig_id: 'OL6-00-000341'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9296r357915_fix'
  tag 'documentable'
  tag legacy: ['SV-64919', 'V-50713']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
