control 'SV-41919' do
  title 'All global address ranges used on unclassified and classified networks must be properly registered with the DoD Network Information Center (NIC).'
  desc 'If network address space is not properly configured, managed, and controlled, the network could be accessed by unauthorized personnel resulting in security compromise of site information and resources. Allowing subscribers onto the network whose IP addresses are not registered with the .Mil NIC may allow unauthorized users access into the network. These unauthorized users could then monitor the network, steal passwords, and access classified information.'
  desc 'check', 'Validate global IP addresses in use on unclassified or classified networks registered through the DoD Network Information Center. For NIPRNet, go to the website https://www.nic.mil. For SIPRNet, go to the web portal at http://www.ssc.smil.mil. To verify Department of the Navy IP addresses, go to  http://infosec.navy.mil.ipaddress.com.

If the site is using an address space that has not been registered and allocated to the site, this is a finding.'
  desc 'fix', 'Submit any unregistered and/or unauthorized global IP addresses to the DoD Network Information Center (NIC) for registration.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-40348r4_chk'
  tag severity: 'medium'
  tag gid: 'V-31632'
  tag rid: 'SV-41919r3_rule'
  tag stig_id: 'NET0180'
  tag gtitle: 'Non-registered or unauthorized IP addresses.'
  tag fix_id: 'F-35552r4_fix'
  tag 'documentable'
  tag responsibility: 'Network Security Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
