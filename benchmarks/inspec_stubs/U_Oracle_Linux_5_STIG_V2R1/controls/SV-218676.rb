control 'SV-218676' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The Stream Control Transmission Protocol (SCTP) is an Internet Engineering Task Force (IETF)-standardized transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the SCTP protocol handler is prevented from dynamic loading.
# grep 'install sctp /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the SCTP protocol handler for dynamic loading.
# echo "install sctp /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20151r556442_chk'
  tag severity: 'medium'
  tag gid: 'V-218676'
  tag rid: 'SV-218676r603259_rule'
  tag stig_id: 'GEN007020'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-20149r556443_fix'
  tag 'documentable'
  tag legacy: ['V-22511', 'SV-63529']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
