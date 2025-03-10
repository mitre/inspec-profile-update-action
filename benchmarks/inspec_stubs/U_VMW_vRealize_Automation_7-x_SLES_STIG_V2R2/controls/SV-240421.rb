control 'SV-240421' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The SCTP is an IETF-standardized transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Verify the SCTP protocol handler is prevented from dynamic loading:

# grep "install sctp /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the SCTP protocol handler for dynamic loading:

# echo "install sctp /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43654r671002_chk'
  tag severity: 'medium'
  tag gid: 'V-240421'
  tag rid: 'SV-240421r671004_rule'
  tag stig_id: 'VRAU-SL-000500'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43613r671003_fix'
  tag 'documentable'
  tag legacy: ['SV-100269', 'V-89619']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
