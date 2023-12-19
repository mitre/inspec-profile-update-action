control 'SV-80931' do
  title 'The Juniper Networks SRX Series Gateway IDPS must either forward the traffic from inbound connections to be more deeply inspected for malicious code and Layer 7 threats, or the Antivirus and Unified Threat Management (UTM) license must be installed, active, and policies and rules configured.'
  desc 'UTM is an industry term that was coined to define Layer 7 protection against client-side threats. This does not include IPS (which also has protection against server-to-client attacks) but rather technologies such as network-based antivirus protection, URL filtering, antispam solutions, and content filtering. IPS is primarily focused on network-based attacks on protocols, and is stream based, meaning that it processes traffic inline without modifying it as a stream. This works great from a performance perspective to detect attacks against services and applications. UTM, on the other hand, is meant more for protecting against files that are transmitted on top of the network streams. Although IPS might be more geared for detecting an overflow of the parser of the network stream, it isn’t as well geared for detecting threats within files. That is, it certainly can detect such file-based attacks, but attackers can go to great lengths to encode, encrypt, and obfuscate files to perform some malicious action—and it is very difficult to detect these attacks in Stream mode.'
  desc 'check', 'Verify UTM and AV policies are configured.

[edit]
show security utm

If a stanza does not exist for at least one UTM and one AV policy, this is a finding.

If the IDPS does not have UTM and AV capabilities and traffic is not forwarded to be inspected for AV and UTM threats, this is a finding.'
  desc 'fix', 'Configure at least one policy for the UTM and AV policy using the commands and options for the [edit security utm] hierarchy.

If the UTM and AV licenses are not installed, IDPS must be installed in the architecture so that traffic is forwarded for deeper AV and UTM inspection. This can be accomplished by using a zone stanza to direct the traffic to an interface or IP destination address.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67087r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66441'
  tag rid: 'SV-80931r1_rule'
  tag stig_id: 'JUSX-IP-000031'
  tag gtitle: 'SRG-NET-000512-IDPS-00194'
  tag fix_id: 'F-72517r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
