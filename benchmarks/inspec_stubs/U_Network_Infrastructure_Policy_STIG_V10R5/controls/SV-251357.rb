control 'SV-251357' do
  title 'If the site has a non-DoD external connection (i.e. Approved Gateway), an Intrusion Detection and Prevention System (IDPS) must be located between the sites Approved Gateway and the perimeter router.'
  desc 'The incorrect placement of the external IDPS may allow unauthorized access to go undetected and limit the ability of security personnel to stop malicious or unauthorized use of the network. In order to ensure that an attempted or existing attack goes unnoticed, the data from the sensors must be monitored continuously.'
  desc 'check', "Inspect the network topology and physical connectivity to verify compliance.

If the site has a non-DoD external connection and does not have an IDPS located between the site's Approved Gateway and the perimeter router, this is a finding.

Note:  An Approved Gateway (AG) is any external connection from a DoD NIPRNet enclave to an Internet Service Provider, or network owned by a contractor, or non-DoD federal agency that has been approved by either the DoD CIO or the DoD Component CIO.  This AG requirement does not apply to commercial cloud connections when the Cloud Service Provider (CSP) network is connected via the NIPRNet Boundary Cloud Access Point (BCAP)."
  desc 'fix', "Install and configure an IDPS between the site's Approved Gateway and the premise router."
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54792r806024_chk'
  tag severity: 'medium'
  tag gid: 'V-251357'
  tag rid: 'SV-251357r806026_rule'
  tag stig_id: 'NET0168'
  tag gtitle: 'NET0168'
  tag fix_id: 'F-54745r806025_fix'
  tag 'documentable'
  tag legacy: ['V-14634', 'SV-15259']
  tag cci: ['CCI-001101', 'CCI-001121']
  tag nist: ['SC-7 (3)', 'SC-7 (14)']
end
