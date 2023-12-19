control 'SV-218072' do
  title 'The snmpd service must not use a default password.'
  desc 'Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system.'
  desc 'check', 'Verify the "snmp" package is installed:

# rpm -qa | grep -i snmp
net-snmp-5.7.1-31.2.x86_64.rpm

If the package is not installed, this is Not Applicable.

To ensure the default password is not set, run the following command: 

# grep -v "^#" /etc/snmp/snmpd.conf| grep public

There should be no output. 

If there is output, this is a finding.'
  desc 'fix', 'Edit "/etc/snmp/snmpd.conf", remove default community string "public". Upon doing that, restart the SNMP service: 

# service snmpd restart'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19553r377231_chk'
  tag severity: 'high'
  tag gid: 'V-218072'
  tag rid: 'SV-218072r603264_rule'
  tag stig_id: 'RHEL-06-000341'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19551r377232_fix'
  tag 'documentable'
  tag legacy: ['SV-50454', 'V-38653']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
