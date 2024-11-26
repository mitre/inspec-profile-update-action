control 'SV-45973' do
  title 'The AppleTalk protocol must be disabled or not installed.'
  desc 'The AppleTalk suite of protocols is no longer in common use.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the AppleTalk protocol handler is prevented from dynamic loading.
# grep 'install appletalk' /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep ‘/bin/true’
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the AppleTalk protocol handler for dynamic loading.
# echo "install appletalk /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43255r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22524'
  tag rid: 'SV-45973r1_rule'
  tag stig_id: 'GEN007260'
  tag gtitle: 'GEN007260'
  tag fix_id: 'F-39338r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
