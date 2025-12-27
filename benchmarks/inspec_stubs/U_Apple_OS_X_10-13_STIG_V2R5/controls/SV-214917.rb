control 'SV-214917' do
  title 'The macOS system must have unused network devices disabled.'
  desc 'If an unused network device is left enabled, a user might be able to activate it at a later time. Unused network devices should be disabled.'
  desc 'check', 'To list the network devices that are enabled on the system, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices

A disabled device will have an asterisk in front of its name.

If any listed device that is not in use is missing this asterisk, this is a finding.'
  desc 'fix', %q(To disable a network device, run the following command, substituting the name of the device in place of "'<networkservice>'":

/usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled '<networkservice>' off)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16117r397323_chk'
  tag severity: 'medium'
  tag gid: 'V-214917'
  tag rid: 'SV-214917r609363_rule'
  tag stig_id: 'AOSX-13-001235'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16115r397324_fix'
  tag 'documentable'
  tag legacy: ['SV-96429', 'V-81715']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
