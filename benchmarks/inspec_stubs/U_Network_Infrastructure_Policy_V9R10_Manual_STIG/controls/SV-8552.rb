control 'SV-8552' do
  title 'When protecting the boundaries of a network, the firewall must be placed between the private network and the perimeter router and the Demilitarized Zone (DMZ).'
  desc 'The only way to mediate the flow of traffic between the inside network, the outside connection, and the DMZ is to place the firewall into the architecture in a manner that allows the firewall the ability to screen content for all three destinations.'
  desc 'check', 'Review the network topology diagrams and visually inspect the firewall location to validate correct position on the network. 

If the firewall is not positioned between the perimeter router and the private network and between the perimeter router and the DMZ, this is a finding.

Exception: If the perimeter security for the enclave or B/C/P/S is provisioned via the JRSS, then this requirement is not applicable.'
  desc 'fix', 'Move the firewall into the prescribed location to allow for enforcement of the Enclave Security Policy and allow for all traffic to be screened.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7447r3_chk'
  tag severity: 'medium'
  tag gid: 'V-8066'
  tag rid: 'SV-8552r3_rule'
  tag stig_id: 'NET0351'
  tag gtitle: 'Firewall placement is not IAW the Network STIG.'
  tag fix_id: 'F-7641r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000262', 'CCI-002073']
  tag nist: ['CA-3 (1)', 'CA-3 (1)']
end
