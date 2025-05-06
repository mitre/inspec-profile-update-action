control 'SV-251353' do
  title 'Network topology diagrams for the enclave must be maintained and up to date at all times.'
  desc 'To assist in the management, auditing, and security of the network infrastructure facility drawings and topology maps are a necessity.  Topology maps are important because they show the overall layout of the network infrastructure and where devices are physically located.  They also show the relationship and interconnectivity between devices and where possible intrusive attacks could take place.  Having up to date network topology diagrams will also help show what the security, traffic, and physical impact of adding a new user(s) will be on the network.'
  desc 'check', 'Validate the network diagram by correlating the information with all routers, multi-layer switches, and firewall configurations.

Validate all subnets have been documented accordingly.

Validate any connectivity documented on the diagram by physically examining the cable connections for the downstream and upstream links, as well as connections for major network components (Routers, Switches, Firewalls, IDS/IPS, etc.).

If the site has not maintained network topology diagrams for the enclave, this is a finding.'
  desc 'fix', "Update the enclave's network topology diagram to represent the current state of the network and its connectivity."
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54788r806012_chk'
  tag severity: 'medium'
  tag gid: 'V-251353'
  tag rid: 'SV-251353r806014_rule'
  tag stig_id: 'NET0090'
  tag gtitle: 'NET0090'
  tag fix_id: 'F-54741r806013_fix'
  tag 'documentable'
  tag legacy: ['V-8046', 'SV-8532']
  tag cci: ['CCI-001098']
  tag nist: ['SC-7 c']
end
