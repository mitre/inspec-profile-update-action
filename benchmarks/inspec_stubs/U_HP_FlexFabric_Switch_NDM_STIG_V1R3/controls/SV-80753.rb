control 'SV-80753' do
  title 'The HP FlexFabric Switch must protect against or limit the effects of all known types of Denial of Service (DoS) attacks on the HP FlexFabric Switch management network by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Check if the HP FlexFabric Switch is configured to protect against known DoS attacks by implementing ACLs and by enabling tcp syn-flood protection:

[HP] display current-configuration

 tcp syn-cookie enable
 tcp timer syn-timeout 10

[HP] display acl all

If the HP FlexFabric Switch is not configured with ACLs and tcp syn-flood features, this is a finding.

Check pre-defined qos policies that are by default applied to the control plane: 

[HP] display qos policy control-plane pre-defined

Check user-defined qos policies:
[HP] display qos policy user-defined'
  desc 'fix', 'Configure the HP FlexFabric Switch to protect against or limit the effects of all known types of DoS attacks by employing organization-defined security safeguards.

Enable the anti-attack function: 

[HP] tcp syn-cookie enable

Configure maximum wait time to establish a TCP connection: 

[HP] tcp timer syn-timeout 10

Configure QoS policy and apply it to the control plane:

[HP] traffic classifier Net-Protocols operator or
[HP-classifier Net-Protocols] if match control-plane protocol icmp
[HP-classifier Net-Protocols] quit
[HP] traffic behavior Net-Protocols
[HP-behavior-Net-Protocols] car cir 320
[HP-behavior-Net-Protocols] quit
[HP] qos policy Net-protocols
[HP-qospolicy-Net-Protocols] classifier Net-Protocols behavior Net-protocols
[HP-qospolicy-Net-Protocols] quit
[HP] control-plane slot 1
[HP-cp-slot1] qos apply policy Net-Protocols inbound

Note: In addition, ACLs can be deployed to address specific types of attacks based on IP, MAC, protocols and ports.

Note: By default, the HP FlexFabric Switches are configured with pre-defined control plane QoS policies, which take effect on the control planes by default.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66263'
  tag rid: 'SV-80753r1_rule'
  tag stig_id: 'HFFS-ND-000118'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-72339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
