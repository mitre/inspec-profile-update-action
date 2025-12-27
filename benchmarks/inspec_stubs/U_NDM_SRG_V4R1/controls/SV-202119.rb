control 'SV-202119' do
  title 'The network device must be configured to protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Determine if the network device protects against or limits the effects of all known types of DoS attacks by employing organization-defined security safeguards.

If the network device does not protect against or limit the effects of all known types of DoS attacks by employing organization-defined security safeguards, this is a finding.'
  desc 'fix', 'Configure the network device to protect against or limit the effects of all known types of DoS attacks by employing organization-defined security safeguards.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2245r382037_chk'
  tag severity: 'medium'
  tag gid: 'V-202119'
  tag rid: 'SV-202119r400402_rule'
  tag stig_id: 'SRG-APP-000435-NDM-000315'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-2246r382038_fix'
  tag 'documentable'
  tag legacy: ['SV-69515', 'V-55269']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
