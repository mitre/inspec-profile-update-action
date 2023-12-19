control 'SV-29988' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The SCTP is an IETF-standardized transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Check the system for an SCTP installation:
# swlist | grep -i SCTP

If SCTP is installed, this is a finding.'
  desc 'fix', 'Configure the system to prevent the dynamic loading of the SCTP protocol handler.
Preview the removal of SCTP:
# swremove -p <SCTP software product>

Remove:
# swremove <SCTP software product>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35070r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22511'
  tag rid: 'SV-29988r1_rule'
  tag stig_id: 'GEN007020'
  tag gtitle: 'GEN007020'
  tag fix_id: 'F-30357r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
