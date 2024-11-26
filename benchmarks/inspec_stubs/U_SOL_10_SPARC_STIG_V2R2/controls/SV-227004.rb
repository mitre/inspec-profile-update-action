control 'SV-227004' do
  title 'A system used for routing must not run other network services or applications.'
  desc 'Installing extraneous software on a system designated as a dedicated router poses a security threat to the system and the network. Should an attacker gain access to the router through the unauthorized software, the entire network is susceptible to malicious activity.'
  desc 'check', 'Ask the SA if the system is a designated router.  If it is not, this is not applicable.

Check the system for non-routing network services.

Procedure:
# netstat -a | grep -i listen
# ps -ef

If non-routing services, including Web servers, file servers, DNS servers, or applications servers, but excluding management services, such as SSH and SNMP, are running on the system, this is a finding.'
  desc 'fix', 'Ensure only authorized software is loaded on a designated router.  Authorized software will be limited to the most current version of routing protocols and SSH for system administration purposes.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29166r485351_chk'
  tag severity: 'medium'
  tag gid: 'V-227004'
  tag rid: 'SV-227004r603265_rule'
  tag stig_id: 'GEN005580'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29154r485352_fix'
  tag 'documentable'
  tag legacy: ['V-4398', 'SV-4398']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
