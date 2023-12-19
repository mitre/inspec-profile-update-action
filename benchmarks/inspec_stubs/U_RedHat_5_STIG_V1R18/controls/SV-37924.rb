control 'SV-37924' do
  title 'A system used for routing must not run other network services or applications.'
  desc 'Installing extraneous software on a system designated as a dedicated router poses a security threat to the system and the network. Should an attacker gain access to the router through the unauthorized software, the entire network is susceptible to malicious activity.'
  desc 'check', "If the system is a VM host and acts as a router solely for the benefit of its client systems, then this rule is not applicable.

Check to see if the system is a router:

# chkconfig --list | grep :on | egrep '(ospf|route|bgp|zebra|quagga)'

If the system is running a routing service, it is a router. If it is not, this is not applicable.

Check the system for non-routing network services.

Procedure:
# netstat -a | grep -i listen
# ps -ef

If non-routing services, including Web servers, file servers, DNS servers, or applications servers, but excluding management services such as SSH and SNMP, are running on the system, this is a finding."
  desc 'fix', 'Ensure only authorized software is loaded on a designated router. Authorized software will be limited to the most current version of routing protocols and SSH for system administration purposes.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37160r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4398'
  tag rid: 'SV-37924r2_rule'
  tag stig_id: 'GEN005580'
  tag gtitle: 'GEN005580'
  tag fix_id: 'F-32418r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
