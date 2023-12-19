control 'SV-13618' do
  title 'The DNS architecture is not documented to include specific roles for each DNS server, the security controls in place, and what networks are able to query each server.'
  desc 'Without current and accurate documentation, any changes to the network infrastructure may
jeopardize the network’s integrity. To assist in the management, auditing, and security of the
network, facility drawings and topology maps are a necessity; and those addressing critical network assets, such as the DNS server, are especially important. Topology maps (documentation) are important because they show the overall layout of the network infrastructure and where devices are
physically located. They also show the relationship and inter-connectivity between devices and
where possible intrusive attacks (wire taps) could take place.
Additionally,  documentation along with diagrams of the network topology are required to be submitted to the Connection Approval Process (CAP) for approval to connect to the NIPRNet or SIPRNet. Depending on the command, service, or activity, additional approval may be required.'
  desc 'check', 'Interview the IAO or SA and ask to see the DNS architecture documentation to include roles for each server, security controls, and the list of networks that are able to query the DNS server.'
  desc 'fix', 'Document the DNS architecture to include the location, function, role, and security controls for all DNS servers.'
  impact 0.3
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-7861r1_chk'
  tag severity: 'low'
  tag gid: 'V-13050'
  tag rid: 'SV-13618r1_rule'
  tag stig_id: 'DNS0160'
  tag gtitle: 'DNS architecture not documented.'
  tag fix_id: 'F-11159r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
