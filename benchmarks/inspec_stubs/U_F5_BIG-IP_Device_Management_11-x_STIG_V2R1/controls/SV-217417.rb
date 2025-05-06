control 'SV-217417' do
  title 'The BIG-IP appliance must be configured to protect against or limit the effects of all known types of Denial of Service (DoS) attacks on the BIG-IP appliance management network by limiting the number of concurrent sessions.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks. 

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Verify the BIG-IP appliance is configured to protect against or to limit the effects of DoS attacks by limiting the number of concurrent sessions. 

Review organizational Standard Operating Procedures (SOP) to ensure there is an organizational-defined threshold for the number of allowed connections to the management console.

Navigate to the BIG-IP System manager >> System >> Preferences.

Set "System Settings:" to "Advanced".

Verify "Maximum HTTP Connections To Configuration Utility" is set to the number of allowed connections defined in the local SOP.

If the BIG-IP appliance is not configured to protect against or limit the effects of DoS attacks by limiting the number of concurrent sessions, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to limit the effects of DoS attacks by employing security safeguards to limit the number of concurrent sessions to the configuration utility.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18642r290805_chk'
  tag severity: 'high'
  tag gid: 'V-217417'
  tag rid: 'SV-217417r557520_rule'
  tag stig_id: 'F5BI-DM-000239'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-18640r290806_fix'
  tag 'documentable'
  tag legacy: ['V-60217', 'SV-74647']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
