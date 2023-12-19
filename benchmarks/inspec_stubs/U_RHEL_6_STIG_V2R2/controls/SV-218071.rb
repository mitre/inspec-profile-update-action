control 'SV-218071' do
  title 'The snmpd service must use only SNMP protocol version 3 or newer.'
  desc 'Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information.'
  desc 'check', %q(Verify the "snmp" package is installed:

# rpm -qa | grep -i snmp
net-snmp-5.7.1-31.2.x86_64.rpm

If the package is not installed, this is Not Applicable.

To ensure only SNMPv3 or newer is used, run the following command: 

# grep 'v1\|v2c\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'

There should be no output. 

If there is output, this is a finding.)
  desc 'fix', 'Edit "/etc/snmp/snmpd.conf", removing any references to "v1", "v2c", or "com2sec". Upon doing that, restart the SNMP service: 

# service snmpd restart'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19552r462415_chk'
  tag severity: 'medium'
  tag gid: 'V-218071'
  tag rid: 'SV-218071r603264_rule'
  tag stig_id: 'RHEL-06-000340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19550r462416_fix'
  tag 'documentable'
  tag legacy: ['SV-50461', 'V-38660']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
