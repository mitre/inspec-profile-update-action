control 'SV-37605' do
  title 'The Bluetooth protocol handler must be disabled or not installed.'
  desc 'Bluetooth is a Personal Area Network (PAN) technology.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the Bluetooth protocol handler is prevented from dynamic loading.
# grep 'install bluetooth /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the Bluetooth protocol handler for dynamic loading.
# echo "install bluetooth /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36766r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22539'
  tag rid: 'SV-37605r1_rule'
  tag stig_id: 'GEN007660'
  tag gtitle: 'GEN007660'
  tag fix_id: 'F-31640r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
