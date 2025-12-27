control 'SV-96901' do
  title 'The MaaS360 server platform must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. The MDM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality. All others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where the MDM server runs on a standalone platform. Network firewalls or other architectures may be preferred where the MDM server runs in a cloud or virtualized solution.

SFR ID: FMT_SMF.1.1(2) b'
  desc 'check', 'Review the implementation of the MaaS360 server with the site System Administrator. Verify a host-based firewall (for example, HBSS) is installed on the Windows server.

If the MaaS360 server is not protected by a DoD-approved firewall, this is a finding.'
  desc 'fix', 'Protect the MaaS360 server with a DoD-approved firewall.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81987r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82187'
  tag rid: 'SV-96901r1_rule'
  tag stig_id: 'M360-10-200100'
  tag gtitle: 'PP-MDM-331004'
  tag fix_id: 'F-89045r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
