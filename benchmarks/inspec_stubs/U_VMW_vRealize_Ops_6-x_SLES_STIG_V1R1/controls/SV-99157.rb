control 'SV-99157' do
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled or not installed unless required.'
  desc 'The Reliable Datagram Sockets (RDS) protocol is a relatively new protocol developed by Oracle for communication between the nodes of a cluster. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Ask the SA if RDS is required by application software running on the system. If so, this is not applicable.

Check that the RDS protocol handler is prevented from dynamic loading:

# grep "install rds /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the RDS protocol handler from dynamic loading:

# echo "install rds /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88199r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88507'
  tag rid: 'SV-99157r1_rule'
  tag stig_id: 'VROM-SL-000495'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
