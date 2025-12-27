control 'SV-242252' do
  title 'The TippingPoint SMS must be configured to protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'In the SMS client, verify the SMS and TPS have DoS protections enabled.

1. Navigate to Devices and select the SMS hostname.
2. Select Device Configuration >> Select Host IP filters. 

If no filters exist or the default action is set to "allow", this is a finding.'
  desc 'fix', 'In the SMS client, ensure the SMS and TPS have DoS protections enabled.

1. Navigate to Devices and select the SMS hostname.
2. Select Device Configuration >> Select Host IP filters. 
3. Add each allowed management subnet. 
4. Select Deny as the default action and click OK. 
5. Select OK.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45527r710761_chk'
  tag severity: 'medium'
  tag gid: 'V-242252'
  tag rid: 'SV-242252r710763_rule'
  tag stig_id: 'TIPP-NM-000490'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-45485r710762_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
