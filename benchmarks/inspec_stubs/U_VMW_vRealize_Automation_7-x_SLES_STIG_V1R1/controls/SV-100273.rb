control 'SV-100273' do
  title 'The Transparent Inter-Process Communication (TIPC) must be disabled or not installed.'
  desc 'The Transparent Inter-Process Communication (TIPC) protocol is a relatively new cluster communications protocol developed by Ericsson. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Verify the TIPC protocol handler is prevented from dynamic loading:

# grep "install tipc /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* 

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the TIPC protocol handler for dynamic loading:

# echo "install tipc /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89315r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89623'
  tag rid: 'SV-100273r1_rule'
  tag stig_id: 'VRAU-SL-000510'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
