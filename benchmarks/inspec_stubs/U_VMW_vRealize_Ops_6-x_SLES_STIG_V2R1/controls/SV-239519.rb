control 'SV-239519' do
  title 'The Transparent Inter-Process Communication (TIPC) must be disabled or not installed.'
  desc 'The Transparent Inter-Process Communication (TIPC) protocol is a relatively new cluster communications protocol developed by Ericsson. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Verify the TIPC protocol handler is prevented from dynamic loading:

# grep "install tipc /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* 

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the TIPC protocol handler from dynamic loading:

# echo "install tipc /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42752r662006_chk'
  tag severity: 'medium'
  tag gid: 'V-239519'
  tag rid: 'SV-239519r662008_rule'
  tag stig_id: 'VROM-SL-000500'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42711r662007_fix'
  tag 'documentable'
  tag legacy: ['SV-99159', 'V-88509']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
