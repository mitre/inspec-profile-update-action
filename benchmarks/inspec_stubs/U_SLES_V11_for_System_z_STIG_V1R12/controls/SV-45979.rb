control 'SV-45979' do
  title 'The Bluetooth protocol handler must be disabled or not installed.'
  desc 'Bluetooth is a Personal Area Network (PAN) technology.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the Bluetooth protocol handler is prevented from dynamic loading.
# grep 'install bluetooth' /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep ‘/bin/true’

If no result is returned, this is a finding."
  desc 'fix', 'Prevent the Bluetooth protocol handler for dynamic loading.
# echo "install bluetooth /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22539'
  tag rid: 'SV-45979r1_rule'
  tag stig_id: 'GEN007660'
  tag gtitle: 'GEN007660'
  tag fix_id: 'F-39344r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
