control 'SV-234217' do
  title 'The FortiGate device must protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS prohibit a resource from being available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD-level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Click on IPv4 DoS Policy or IPv6 DoS Policy.
3. Identify the port designated for FortiGate device management.
4. Select the policy and click Edit.
5. Verify appropriate L3 Anomalies and L4 Anomalies are configured to meet the organization requirement.
6. Verify the policy is Enabled.

If appropriate DoS policies are not defined or are disabled, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 DoS Policy or IPv6 DoS Policy.
3. Identify the port designated for FortiGate device management.
4. Click +Create New.
5. Define the Incoming Interface, Source Address, Destination Address, and Services.
6. Configure L3 Anomalies, and L4 Anomalies to meet the organization requirement.
7. Click OK.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37402r611838_chk'
  tag severity: 'medium'
  tag gid: 'V-234217'
  tag rid: 'SV-234217r850538_rule'
  tag stig_id: 'FGFW-ND-000290'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-37367r611839_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
