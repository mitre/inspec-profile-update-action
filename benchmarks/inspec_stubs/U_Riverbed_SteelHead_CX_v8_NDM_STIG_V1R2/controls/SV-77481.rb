control 'SV-77481' do
  title 'Riverbed Optimization System (RiOS) must protect against or limit the effects of all known types of Denial of Service (DoS) attacks on the network device management network by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Verify that RIOS is configured to protect against or limit the effects of all know types of Denial of Service (DoS) attacks on the device management network.

Navigate to the device Management Console
Navigate to Configure >> Security >> Management ACL
Verify that there is a rule to limit management access from authorized devices and that the interface is set to other than an in-path interface
Verify that "Enable Management ACL" is checked

If Management ACLs are not defined to limit access to identified or known devices and/or a management interface is not defined that is different from the in-path interface and/or "Enable Management ACL" is not checked, this is a finding.'
  desc 'fix', 'Configure RiOS to protect against or limit the effects of all known types of Denial of Service (DoS) attacks on the network device management network.

Navigate to the device Management Console
Navigate to Configure >> Security >> Management ACL
Click "Add a New Rule"
Set "Action" to "Allow"
Set "Service" to "HTTPS"
Set "Source Network" to Management device network
Set "Interface" to the interface used for network management
Set "Description" to enable ease of management
Click "Add"
Click "Add a New Rule" and repeat all actions for SSH
Click "Enable Management ACL"
Click "Apply"

Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62991'
  tag rid: 'SV-77481r1_rule'
  tag stig_id: 'RICX-DM-000143'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-68909r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
