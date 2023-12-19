control 'SV-13600' do
  title 'A name server is not protected by equivalent or better physical access controls than the clients it supports.'
  desc 'If an adversary can compromise a name server, then the adversary can redirect most network traffic sent to the hosts defined on that name server.  Therefore, the security of the name server is as critical as the security of the hosts it protects.  It is understood that different hosts require different levels of physical security.  Nevertheless, the name server should not have weaker physical access controls than the computers it supports because this would, in effect, reduce the security of those hosts as well.'
  desc 'check', 'Ask to see the locations at the facility where computers supported by the listed name server(s) under evaluation are located (e.g., server closets, raised floor space, etc.).  Note those areas that have the most extensive physical security controls.  Also ask to see the locations of the name servers themselves.  Then compare the physical security of the most secure computers against the physical security of the name server under evaluation.  If the name server has substantially weaker physical security controls than the hosts it supports (e.g., the name server is in the DNS administrator’s cube while the servers are in a locked cage in a secure raised floor area), then this is a finding.'
  desc 'fix', 'Working with appropriate technical and facility personnel, the IAO should arrange to relocate the name server into the same physical location as the most sensitive hosts it supports.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3336r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13032'
  tag rid: 'SV-13600r1_rule'
  tag stig_id: 'DNS0100'
  tag gtitle: 'A name server is not physically protected'
  tag fix_id: 'F-4336r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
