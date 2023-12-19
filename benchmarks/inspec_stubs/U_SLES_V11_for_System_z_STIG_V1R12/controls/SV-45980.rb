control 'SV-45980' do
  title 'The IPv6 protocol handler must not be bound to the network stack unless needed.'
  desc 'IPv6 is the next version of the Internet protocol.  Binding this protocol to the network stack increases the attack surface of the host.'
  desc 'check', 'Use the ifconfig command to determine if any network interface has an IPv6 address bound to it:
# /sbin/ifconfig | grep inet6

If any lines are returned that indicate IPv6 is active and the system does not need IPv6, this is a finding.'
  desc 'fix', 'Remove the capability to use IPv6 protocol handler.

Procedure:
Update the variable “IPV6_DISABLE” using YaST in the /etc/sysconfig editor under the ‘System’ > ‘Kernel’ tree.  Setting this variable to “YES” deactivates IPv6 at boot time.  Reboot the system to implement the change.

NOTE: This change may affect other software product(s) that have their own IPv6 configuration settings.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43262r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22541'
  tag rid: 'SV-45980r1_rule'
  tag stig_id: 'GEN007700'
  tag gtitle: 'GEN007700'
  tag fix_id: 'F-39345r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
