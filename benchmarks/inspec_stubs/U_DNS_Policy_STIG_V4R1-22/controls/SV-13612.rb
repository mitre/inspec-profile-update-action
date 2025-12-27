control 'SV-13612' do
  title 'A zone includes hosts located in more than one building or site, yet at least one of the authoritative name servers supporting the zone is not as geographically and topologically distributed as the most remote host.'
  desc 'When authoritative name servers are co-located in the same facility, the loss of the facility likely leads to the loss of access to all servers defined in their zones (i.e., nobody can resolve their names).  If one or more of the hosts in the supported zones are located at a different site, they would be effectively down even though they would otherwise be fully operational.  This scenario can only be prevented with geographic dispersal of name servers.  Organizations should also be prepared for greater disasters, such as the destruction of a building, an entire campus, or in the case of a hurricane, an entire city.  In situations in which all the hosts defined on an authoritative name server are located in the same building as the name server, then loss of DNS will not impact availability of service simply because the computing infrastructure is already down.  On the other hand, if all the authoritative name servers for a zone reside in a single building, but hosts defined within the zone are located elsewhere, then the loss of the DNS will impact service.  The loss of service occurs because users (and other infrastructure devices and servers) will not be able to resolve host names for servers/services that are otherwise still operational at an unaffected site.'
  desc 'check', 'By examining the zone file, the reviewer can determine whether there are hosts defined on one of the name server’s zones that reside in more than one building.  If they all reside in the same building, then this check does not apply.  If the defined hosts reside in different buildings, then one of the evaluated name server’s zone partners (slave or master) must reside in an alternate building.  In this case, if all of the authoritative name servers for a zone reside in the same building, then this a finding.   *Note:  If the the zones records are on one subnet a single nameserver is required.'
  desc 'fix', 'Working with DNS administrators and appropriate technical and facility personnel, the IAO should either arrange for one of the existing name servers to be moved to different location, deploy an additional name server at another location, or arrange to have an existing name server at another location act as slave to the zones hosted at the current location.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3427r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13044'
  tag rid: 'SV-13612r1_rule'
  tag stig_id: 'DNS0210'
  tag gtitle: 'Name servers are not geographically distributed.'
  tag fix_id: 'F-4349r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
