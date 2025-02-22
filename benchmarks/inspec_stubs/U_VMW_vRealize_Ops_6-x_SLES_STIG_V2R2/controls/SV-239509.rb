control 'SV-239509' do
  title 'The Bluetooth protocol handler must be disabled or not installed.'
  desc 'Bluetooth is a personal area network (PAN) technology. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Verify the Bluetooth protocol handler is prevented from dynamic loading:

# grep "install bluetooth /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the Bluetooth protocol handler for dynamic loading:

# echo "install bluetooth /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42742r661976_chk'
  tag severity: 'medium'
  tag gid: 'V-239509'
  tag rid: 'SV-239509r661978_rule'
  tag stig_id: 'VROM-SL-000440'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-42701r661977_fix'
  tag 'documentable'
  tag legacy: ['SV-99139', 'V-88489']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
