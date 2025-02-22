control 'SV-239932' do
  title 'The Cisco ASA must be configured to protect against known types of Denial of Service (DoS) attacks by enabling the 
Threat Detection feature.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Review the ASA configuration and verify the Threat Detection feature is enabled as shown in the example below.

threat-detection basic-threat

If the Cisco ASA does not have the Threat Detection feature enabled, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to protect against known types of DoS attacks by enabling the Threat Detection feature.

ASA(config)# threat-detection basic-threat   
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43165r666157_chk'
  tag severity: 'medium'
  tag gid: 'V-239932'
  tag rid: 'SV-239932r851037_rule'
  tag stig_id: 'CASA-ND-001180'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-43124r666158_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
