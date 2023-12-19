control 'SV-46101' do
  title 'The Internetwork Packet Exchange (IPX) protocol must be disabled or not installed.'
  desc 'The IPX protocol is a network-layer protocol no longer in common use.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Check that the IPX protocol handler is prevented from dynamic loading.
# grep 'install ipx' /etc/modprobe.conf /etc/modprbe.conf.local /etc/modprobe.d/* | grep ‘/bin/true’
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the IPX protocol handler for dynamic loading.
# echo "install ipx /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43358r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22520'
  tag rid: 'SV-46101r1_rule'
  tag stig_id: 'GEN007200'
  tag gtitle: 'GEN007200'
  tag fix_id: 'F-39445r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
