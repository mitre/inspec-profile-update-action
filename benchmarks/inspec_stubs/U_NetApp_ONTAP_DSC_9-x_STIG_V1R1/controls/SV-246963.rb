control 'SV-246963' do
  title 'ONTAP must be configured to protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Use "system services firewall policy show" to show firewall policies that are currently configured.

If ONTAP cannot be configured to protect against known types of DoS attacks, this is a finding.'
  desc 'fix', 'Configure ONTAP against know types of DoS with the "system services firewall policy create" command. Apply the policy with the "network interface modify -lif lifname -firewall-policy" command.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50395r769219_chk'
  tag severity: 'medium'
  tag gid: 'V-246963'
  tag rid: 'SV-246963r769221_rule'
  tag stig_id: 'NAOT-SC-000005'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-50349r769220_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
