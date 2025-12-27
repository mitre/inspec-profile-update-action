control 'SV-26186' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The Stream Control Transmission Protocol (SCTP) is an IETF-standardized transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no SCTP protocol handler for the system, this is not applicable.
Determine if the system is configured to prevent the dynamic loading of the SCTP protocol handler.  If not, this is a finding.'
  desc 'fix', 'Configure the system to prevent the dynamic loading of the SCTP protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29281r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22511'
  tag rid: 'SV-26186r1_rule'
  tag stig_id: 'GEN007020'
  tag gtitle: 'GEN007020'
  tag fix_id: 'F-26313r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
