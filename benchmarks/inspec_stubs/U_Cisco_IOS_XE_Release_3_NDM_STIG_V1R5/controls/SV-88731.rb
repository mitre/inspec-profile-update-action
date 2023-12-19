control 'SV-88731' do
  title 'The Cisco IOS XE router must protect against or limit the effects of all known types of Denial of Service (DoS) attacks on network device management network by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Determine whether control plane protection has been implemented on the Cisco IOS XE router by verifying traffic types have been classified based on importance levels and a policy has been configured to filter and rate limit the traffic according to each class.

The configuration should look similar to the following example:

class-map match-any CoPP_UNDESIRABLE
 match access-group name CoPP_UNDESIRABLE
class-map match-any CoPP_IMPORTANT
 match access-group name CoPP_IMPORTANT
 match protocol arp
class-map match-all CoPP_DEFAULT
 match access-group name CoPP_DEFAULT

policy-map CONTROL_PLANE_POLICY
 class CoPP_CRITICAL
  police 512000 8000 conform-action transmit  exceed-action transmit 
 class CoPP_IMPORTANT
  police 256000 4000 conform-action transmit  exceed-action drop 
 class CoPP_NORMAL
  police 128000 2000 conform-action transmit  exceed-action drop 
 class CoPP_UNDESIRABLE
  police 8000 1000 conform-action drop  exceed-action drop 
 class CoPP_DEFAULT
  police 64000 1000 conform-action transmit  exceed-action drop 

If control plane protection has not been implemented, this is a finding.

If control plane protection has been implemented but is not configured to verify traffic types have been classified based on importance levels and a policy has been configured to filter and rate limit the traffic according to each class, this is a finding.'
  desc 'fix', 'Implement control plane protection by classifying traffic types based on importance and configure filters to restrict and rate limit the traffic directed to and processed by the route processor according to each class.

The configuration would look similar to the one below:

class-map match-any CoPP_UNDESIRABLE
 match access-group name CoPP_UNDESIRABLE
class-map match-any CoPP_IMPORTANT
 match access-group name CoPP_IMPORTANT
 match protocol arp
class-map match-all CoPP_DEFAULT
 match access-group name CoPP_DEFAULT

policy-map CONTROL_PLANE_POLICY
 class CoPP_CRITICAL
  police 512000 8000 conform-action transmit  exceed-action transmit 
 class CoPP_IMPORTANT
  police 256000 4000 conform-action transmit  exceed-action drop 
 class CoPP_NORMAL
  police 128000 2000 conform-action transmit  exceed-action drop 
 class CoPP_UNDESIRABLE
  police 8000 1000 conform-action drop  exceed-action drop 
 class CoPP_DEFAULT
  police 64000 1000 conform-action transmit  exceed-action drop'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74147r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74057'
  tag rid: 'SV-88731r2_rule'
  tag stig_id: 'CISR-ND-000119'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-80599r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
