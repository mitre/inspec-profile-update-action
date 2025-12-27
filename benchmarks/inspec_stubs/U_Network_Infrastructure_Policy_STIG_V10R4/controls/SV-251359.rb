control 'SV-251359' do
  title 'All global address ranges used on unclassified and classified networks must be properly registered with the DoD Network Information Center (NIC).'
  desc 'If network address space is not properly configured, managed, and controlled, the network could be accessed by unauthorized personnel resulting in security compromise of site information and resources. Allowing subscribers onto the network whose IP addresses are not registered with the .Mil NIC may allow unauthorized users access into the network. These unauthorized users could then monitor the network, steal passwords, and access classified information.'
  desc 'check', 'Validate global IP addresses in use on unclassified or classified networks registered through the DoD Network Information Center. For NIPRNet, go to the website https://www.nic.mil. For SIPRNet, go to the web portal at http://www.ssc.smil.mil.

If the site is using an address space that has not been registered and allocated to the site, this is a finding.'
  desc 'fix', 'Submit any unregistered and/or unauthorized global IP addresses to the DoD Network Information Center (NIC) for registration.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54794r877973_chk'
  tag severity: 'medium'
  tag gid: 'V-251359'
  tag rid: 'SV-251359r877974_rule'
  tag stig_id: 'NET0180'
  tag gtitle: 'NET0180'
  tag fix_id: 'F-54747r806031_fix'
  tag 'documentable'
  tag legacy: ['V-31632', 'SV-41919']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
