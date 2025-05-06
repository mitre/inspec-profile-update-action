control 'SV-90837' do
  title 'The OS X system must have unused network devices disabled.'
  desc 'If an unused network device is left enabled, a user might be able to activate it at a later time. Unused network devices should be disabled.'
  desc 'check', 'To list the network devices that are enabled on the system, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices

A disabled device will have an asterisk in front of its name.

If any listed device that is not in use is missing this asterisk, this is a finding.'
  desc 'fix', %q(To disable a network device, run the following command, substituting the name of the device in place of "'<networkservice>'":

/usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled '<networkservice>' off)
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76149'
  tag rid: 'SV-90837r1_rule'
  tag stig_id: 'AOSX-12-001235'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82787r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
