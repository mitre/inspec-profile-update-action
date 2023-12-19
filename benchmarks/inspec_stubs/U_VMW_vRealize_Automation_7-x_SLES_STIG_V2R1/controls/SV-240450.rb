control 'SV-240450' do
  title 'The AppleTalk protocol must be disabled or not installed.'
  desc 'The AppleTalk suite of protocols is no longer in common use. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Verify the AppleTalk protocol handler is prevented from dynamic loading:

# grep "install appletalk /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* 

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the AppleTalk protocol handler for dynamic loading:

# echo "install appletalk /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43683r671089_chk'
  tag severity: 'medium'
  tag gid: 'V-240450'
  tag rid: 'SV-240450r671091_rule'
  tag stig_id: 'VRAU-SL-000645'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43642r671090_fix'
  tag 'documentable'
  tag legacy: ['SV-100327', 'V-89677']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
