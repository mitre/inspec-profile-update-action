control 'SV-38960' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The Stream Control Transmission Protocol (SCTP) is an IETF-standardized transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Check the system to determine if SCTP is installed.

# lslpp -L bos.net.\\*

If the bos.net.sctp fileset is not listed, SCTP is not installed, and this is not a finding.

If the bos.net.sctp fileset is installed, ask the SA if SCTP is required for the system.  If it is not, this is a finding.'
  desc 'fix', 'If SCTP is installed and not required, unload it from the kernel and uninstall it from the system.

# sctpctrl unload

Use SMIT to uninstall the bos.net.sctp fileset.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38244r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22511'
  tag rid: 'SV-38960r1_rule'
  tag stig_id: 'GEN007020'
  tag gtitle: 'GEN007020'
  tag fix_id: 'F-32345r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
