control 'SV-239517' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The Stream Control Transmission Protocol (SCTP) is an IETF-standardized transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Verify the SCTP protocol handler is prevented from dynamic loading:

# grep "install sctp /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the SCTP protocol handler from dynamic loading:

# echo "install sctp /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42750r662000_chk'
  tag severity: 'medium'
  tag gid: 'V-239517'
  tag rid: 'SV-239517r662002_rule'
  tag stig_id: 'VROM-SL-000490'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42709r662001_fix'
  tag 'documentable'
  tag legacy: ['SV-99155', 'V-88505']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
