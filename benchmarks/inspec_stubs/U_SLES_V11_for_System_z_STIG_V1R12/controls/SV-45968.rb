control 'SV-45968' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The Stream Control Transmission Protocol (SCTP) is an Internet Engineering Task Force (IETF)-standardized transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the SCTP protocol handler is prevented from dynamic loading.
# grep 'install sctp' /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep ‘/bin/true’

If no result is returned, this is a finding."
  desc 'fix', 'Prevent the SCTP protocol handler for dynamic loading.
# echo "install sctp /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43251r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22511'
  tag rid: 'SV-45968r1_rule'
  tag stig_id: 'GEN007020'
  tag gtitle: 'GEN007020'
  tag fix_id: 'F-39333r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
