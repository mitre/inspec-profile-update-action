control 'SV-80875' do
  title 'The Juniper Networks SRX Series Gateway IDPS must restrict or block harmful or suspicious communications traffic between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'The IDPS enforces approved authorizations by controlling the flow of information between interconnected networks to prevent harmful or suspicious traffic does spread to these interconnected networks.

Information flow control policies and restrictions govern where information is allowed to travel as opposed to who is allowed to access the information. The IDPS includes policy filters, rules, signatures, and behavior analysis algorithms that inspects and restricts traffic based on the characteristics of the information and/or the information path as it crosses external/perimeter boundaries. IDPS components are installed and configured such that they restrict or block detected harmful or suspect information flows based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

Once an attack object in the IPS policy is matched, the SRX can execute an action on that specific session, along with actions on future sessions. The ability to execute an action on that particular session is known as an IDPS action. IDPS actions can be one of the following: No-Action, Drop-Packet, Drop-Connection, Close-Client, Close-Server, Close-Client-and-Server, DSCP-Marking, Recommended, or Ignore. IP actions are actions that can be enforced on future sessions. These actions include IP-Close, IP-Block, and IP-Notify

This includes traffic between interfaces that are associated within the same security zone (intra-zone traffic). Traffic is permitted between security zones by configuring security policies from a source security zone to the destination security zone. IDPS inspection will only be performed on the traffic matching the security policies where IDPS is enabled.'
  desc 'check', 'Verify custom rules exist to drop packets or terminate sessions upon detection of malicious code.

[edit]
show security idp policy

View the rulebase action option for the IDP policies. View the action options of the zone configurations with the IDP option.

If rulebases in active policies are configured for No-Action or Ignore when harmful or suspicious content is detected by signatures, rules, or policies, this is a finding.'
  desc 'fix', 'Specify an active IDP policy prior to enabling IDP within a security policy. To configure the active IDP policy, execute the following command in configuration mode:

[edit]
set security idp active-policy <policy name>

Configure Security Policies for IDP inspection. Once the IDP policy is configured, IDP must be enabled on a security policy in order for IDP inspection to be performed. IDP inspection will only be performed on the traffic matching the security policies where IDP is enabled.

To enable IDP on a security policy, enter the following command:

[edit]
set security policies from-zone <FROM ZONE NAME> to-zone <TO ZONE NAME> policy <POLICY NAME> then permit application-services idp'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67031r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66385'
  tag rid: 'SV-80875r1_rule'
  tag stig_id: 'JUSX-IP-000003'
  tag gtitle: 'SRG-NET-000019-IDPS-00019'
  tag fix_id: 'F-72461r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
