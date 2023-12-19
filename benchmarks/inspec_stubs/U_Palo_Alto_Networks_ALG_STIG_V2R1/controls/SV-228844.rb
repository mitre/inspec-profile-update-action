control 'SV-228844' do
  title 'The Palo Alto Networks security platform must deny outbound IP packets that contain an illegitimate address in the source address field.'
  desc %q(A compromised host in an enclave can be used by a malicious actor as a platform to launch cyber attacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack (usually DDoS) other computers or networks. DDoS attacks frequently leverage IP source address spoofing, in which packets with false source IP addresses send traffic to multiple hosts, who then send return traffic to the hosts with the IP addresses that were forged. This can generate significant, even massive, amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken.

Enclaves must enforce egress filtering. In egress filtering, packets leaving the enclave are discarded if the source IP address is not part of the IP address network(s), also known as prefixes, which are assigned to the enclave. A more specific form of egress filtering is to allow only those hosts and protocols that have been identified and authorized to exit the enclave. All traffic leaving the enclave, regardless of the destination, must be filtered by the premise router's egress filter to verify that the source IP address belongs to the enclave.

Configure a security policy that allows only traffic originating from the IP address prefixes assigned to the enclave to exit the enclave.  The implicit deny cross zone traffic rule will then be used, in part, to deny illegitimate source address traffic originating from an internal zone to go to another zone.)
  desc 'check', 'Verify an anti-spoofing policy is configured for each outgoing zone that drops any traffic when the source IP does not match the list of allowed IP ranges for each outgoing zone.

Navigate to the “Zone Protection Profile” configuration screen

Select the “Packet-Based Attack Protection” tab

Select the “IP Drop” tab

If the “Spoofed IP Address” box is not checked for each outgoing zone, this is a finding.'
  desc 'fix', 'Create an anti-spoofing policy for each outgoing zone that drops any traffic when the source IP does not match the list of allowed IP ranges for each outgoing zone.

Navigate to the “Zone Protection Profile” configuration screen.

Select the “Packet- Based Attack Protection” tab.

Select the “IP Drop” tab.

Check the “Spoofed IP Address” box.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31079r513827_chk'
  tag severity: 'medium'
  tag gid: 'V-228844'
  tag rid: 'SV-228844r557387_rule'
  tag stig_id: 'PANW-AG-000050'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-31056r513828_fix'
  tag 'documentable'
  tag legacy: ['V-62571', 'SV-77061']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
