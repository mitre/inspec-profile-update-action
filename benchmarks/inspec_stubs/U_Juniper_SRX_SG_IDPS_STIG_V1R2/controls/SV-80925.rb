control 'SV-80925' do
  title 'The Juniper Networks SRX Series Gateway IDPS must drop packets or disconnect the connection when malicious code is detected.'
  desc 'Configuring the IDPS to discard and/or redirect based on local organizational incident handling procedures minimizes the impact of this code on the network.

Once an attack object in the IPS policy is matched, the SRX can execute an action on that specific session, along with actions on future sessions. The ability to execute an action on that particular session is known as an IDPS action. IDPS actions can be one of the following: No-Action, Drop-Packet, Drop-Connection, Close-Client, Close-Server, Close-Client-and-Server, DSCP-Marking, Recommended, or Ignore. IP actions are actions that can be enforced on future sessions. These actions include IP-Close, IP-Block, and IP-Notify'
  desc 'check', 'Verify custom rules exist to drop packets or terminate sessions upon detection of malicious code.

[edit]
show security idp policy

View the rulebase action option for the IDP policies.

If rulebases for IDP policies which detect malicious code are not configured with an action of Drop-Packet, Drop-Connection, or some form of session termination, this is a finding.'
  desc 'fix', 'This requirement can be met through a custom rule within a policy or drop action option on the zone configuration to which the policy is applied. The following is an example of the command that can be added to the IDP policy. The policy is called Malicious-Activity and the rule is called R1 in this example.

[edit]
set security idp idp-policy Malicious-Activity rulebase-ips rule R1 then action drop-connection'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66435'
  tag rid: 'SV-80925r1_rule'
  tag stig_id: 'JUSX-IP-000028'
  tag gtitle: 'SRG-NET-000249-IDPS-00176'
  tag fix_id: 'F-72511r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
