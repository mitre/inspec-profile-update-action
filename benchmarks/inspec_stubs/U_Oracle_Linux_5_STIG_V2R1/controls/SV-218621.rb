control 'SV-218621' do
  title 'A system used for routing must not run other network services or applications.'
  desc 'Installing extraneous software on a system designated as a dedicated router poses a security threat to the system and the network. Should an attacker gain access to the router through the unauthorized software, the entire network is susceptible to malicious activity.'
  desc 'check', "If the system is a VM host and acts as a router solely for the benefit of its client systems, then this rule is not applicable.

Check to see if the system is a router:

# chkconfig --list | grep :on | egrep '(ospf|route|bgp|zebra|quagga)'

If the system is running a routing service, it is a router.

If it is not, this is not applicable.

Check the system for non-routing network services.

Procedure:

# netstat -a | grep -i listen
# ps -ef

If non-routing services, including Web servers, file servers, DNS servers, or applications servers, but excluding management services such as SSH and SNMP, are running on the system, this is a finding."
  desc 'fix', 'Ensure only authorized software is loaded on a designated router. Authorized software will be limited to the most current version of routing protocols and SSH for system administration purposes.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20096r562852_chk'
  tag severity: 'medium'
  tag gid: 'V-218621'
  tag rid: 'SV-218621r603259_rule'
  tag stig_id: 'GEN005580'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20094r562853_fix'
  tag 'documentable'
  tag legacy: ['V-4398', 'SV-64109']
  tag cci: ['CCI-000381', 'CCI-001208']
  tag nist: ['CM-7 a', 'SC-32']
end
