control 'SV-16799' do
  title 'SNMP write mode is enabled on ESX Server.'
  desc 'The Simple Network Management Protocol (SNMP) is an application-layer protocol used for exchanging management information between network devices. There are four types of SNMP commands that may be used to control and monitor managed devices. These include read, write, trap, and traversal operations. The read command is used to monitor devices, while the write command is used to configure devices and change device settings. The trap command is used to "trap" events from the device and report them back to the monitoring system. Traversal operations are used to determine the variables specific devices support. 

The ESX Server SNMP package is setup by default in a secure configuration. The configuration has a single community string with read-only access which is the default mode. This is denoted by the “ro” community configuration parameter in the configuration file for the master snmpd daemon, snmpd.conf. Furthermore, the UNIX SRR scripts check for proper snmpd.conf and MIB permissions, and snmpd.conf and MIB ownership. They also check to ensure that the default community strings have been changed, and if there is a dedicated SNMP server configured.'
  desc 'check', 'Log into the ESX Server service console and perform the following.
# grep rwcommunity /etc/snmp/snmpd.conf

If the command returns a result, then this is a finding.'
  desc 'fix', 'Disable SNMP write mode.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16215r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15858'
  tag rid: 'SV-16799r1_rule'
  tag stig_id: 'ESX0590'
  tag gtitle: 'SNMP write mode is enabled on ESX Server.'
  tag fix_id: 'F-15818r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end
