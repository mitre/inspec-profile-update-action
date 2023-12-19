control 'SV-26192' do
  title 'The Lightweight User Datagram Protocol (UDP-Lite) must be disabled unless required.'
  desc 'The Lightweight User Datagram Protocol (UDP-Lite) is a proposed transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no UDP-Lite protocol handler available for the system, this is not applicable.
Determine if the UDP-Lite protocol handler is prevented from dynamic loading. If it is not, this is a finding.'
  desc 'fix', 'Configure the system to prevent the dynamic loading of the UDP-Lite protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29285r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22517'
  tag rid: 'SV-26192r1_rule'
  tag stig_id: 'GEN007140'
  tag gtitle: 'GEN007140'
  tag fix_id: 'F-26317r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
