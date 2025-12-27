control 'SV-4398' do
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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8276r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4398'
  tag rid: 'SV-4398r2_rule'
  tag stig_id: 'GEN005580'
  tag gtitle: 'GEN005580'
  tag fix_id: 'F-4309r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSP-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
