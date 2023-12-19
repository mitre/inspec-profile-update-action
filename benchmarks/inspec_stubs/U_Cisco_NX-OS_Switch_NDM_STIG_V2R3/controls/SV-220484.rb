control 'SV-220484' do
  title 'The Cisco switch must produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the network device provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Step 1: Review the deny statements in all interface ACLs to determine if the log parameter has been configured as shown in the example below:

ip access-list extended BLOCK_INBOUND
 deny icmp any any log

Step 2: Verify that the Optimized Access-list Logging (OAL) has been configured.

logging ip access-list cache entries nnnn

Note: Once OAL has been enabled, the logged ACL hits can be viewed via the show log ip access-list cache command.

If the switch is not configured with the log-input parameter after any deny statements to note where packets have been dropped via an ACL, this is a finding.'
  desc 'fix', 'Enable OAL as shown in the example below:

SW1(config)# logging ip access-list cache entries nnnn

Set the ‘log’ parameter after any ‘deny’ entries in the ACL as referenced in the check text above.'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22199r539173_chk'
  tag severity: 'medium'
  tag gid: 'V-220484'
  tag rid: 'SV-220484r604141_rule'
  tag stig_id: 'CISC-ND-000290'
  tag gtitle: 'SRG-APP-000097-NDM-000227'
  tag fix_id: 'F-22188r621700_fix'
  tag 'documentable'
  tag legacy: ['SV-110617', 'V-101513']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
