control 'SV-220439' do
  title 'The Cisco switch must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.'
  desc 'The use of POTS lines to modems connecting to network devices provides clear text of authentication traffic over commercial circuits that could be captured and used to compromise the network. Additional war dial attacks on the device could degrade the device and the production network. 

Secured modem devices must be able to authenticate users and must negotiate a key exchange before full encryption takes place. The modem will provide full encryption capability (Triple DES) or stronger. The technician who manages these devices will be authenticated using a key fob and granted access to the appropriate maintenance port; thus, the technician will gain access to the managed device. The token provides a method of strong (two-factor) user authentication. The token works in conjunction with a server to generate one-time user passwords that will change values at second intervals. The user must know a personal identification number (PIN) and possess the token to be allowed access to the device.'
  desc 'check', 'Review the configuration and verify that the auxiliary port is disabled unless a secured modem providing encryption and authentication is connected to it. 

line aux 0 
 no exec 

Note: transport input none is the default; hence, it will not be shown in the configuration. 

If the auxiliary port is not disabled or is not connected to a secured modem when it is enabled, this is a finding.'
  desc 'fix', 'Disable the auxiliary port. 

SW2(config)#line aux 0 
SW2(config-line)#no exec 
SW2(config-line)#transport input none'
  impact 0.3
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22154r508402_chk'
  tag severity: 'low'
  tag gid: 'V-220439'
  tag rid: 'SV-220439r622190_rule'
  tag stig_id: 'CISC-RT-000230'
  tag gtitle: 'SRG-NET-000019-RTR-000001'
  tag fix_id: 'F-22143r508403_fix'
  tag 'documentable'
  tag legacy: ['SV-110725', 'V-101621']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
