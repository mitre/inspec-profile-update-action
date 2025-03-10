control 'SV-13616' do
  title 'Hosts outside an enclave can directly query or request a zone transfer from a name server that resides on the internal network (i.e., not in a DMZ).'
  desc 'If external hosts are able to query a name server on the internal network, then there is the potential that an external adversary can obtain information about internal hosts that could assist the adversary in a network attack.  External hosts should never be able to learn about the internal network in this manner.'
  desc 'check', 'Work with the Network administrator to determine whether external hosts are able to query a name server on the internal network.  DNS runs on ports 53/TCP for zone transfers and 53/UDP for queries. These ports should be blocked at the firewall or router to internal DNS servers.  If external hosts are able to query a name server on the internal network, then this is a finding.'
  desc 'fix', 'Working with appropriate technical personnel, the IAO should establish firewall rules and/or router ACLs that prohibit access to the name server from external hosts.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3481r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13048'
  tag rid: 'SV-13616r1_rule'
  tag stig_id: 'DNS0405'
  tag gtitle: 'Hosts can directly query an inside name server.'
  tag fix_id: 'F-4357r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
