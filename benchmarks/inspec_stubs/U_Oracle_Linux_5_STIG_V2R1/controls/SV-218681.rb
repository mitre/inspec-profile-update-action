control 'SV-218681' do
  title 'The Bluetooth protocol handler must be disabled or not installed.'
  desc 'Bluetooth is a Personal Area Network (PAN) technology.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the Bluetooth protocol handler is prevented from dynamic loading.
# grep 'install bluetooth /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the Bluetooth protocol handler for dynamic loading.
# echo "install bluetooth /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20156r562924_chk'
  tag severity: 'medium'
  tag gid: 'V-218681'
  tag rid: 'SV-218681r603259_rule'
  tag stig_id: 'GEN007660'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20154r562925_fix'
  tag 'documentable'
  tag legacy: ['V-22539', 'SV-63447']
  tag cci: ['CCI-001551', 'CCI-000381']
  tag nist: ['AC-4', 'CM-7 a']
end
