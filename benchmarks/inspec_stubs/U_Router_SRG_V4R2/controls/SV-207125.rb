control 'SV-207125' do
  title 'The router must be configured to authenticate all routing protocol messages using NIST-validated FIPS 198-1 message authentication code algorithm.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

Since MD5 is vulnerable to "birthday" attacks and may be compromised, routing protocol authentication must use FIPS 198-1 validated algorithms and modules to encrypt the authentication key. This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration to verify it is using a NIST-validated FIPS 198-1 message authentication code algorithm to authenticate routing protocol messages.

If a NIST-validated FIPS 198-1 message authentication code algorithm is not being used to authenticate routing protocol messages, this is a finding.'
  desc 'fix', 'Configure routing protocol authentication to use a NIST-validated FIPS 198-1 message authentication code algorithm.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7386r382268_chk'
  tag severity: 'medium'
  tag gid: 'V-207125'
  tag rid: 'SV-207125r604135_rule'
  tag stig_id: 'SRG-NET-000168-RTR-000078'
  tag gtitle: 'SRG-NET-000168'
  tag fix_id: 'F-7386r382269_fix'
  tag 'documentable'
  tag legacy: ['V-55767', 'SV-70021']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
