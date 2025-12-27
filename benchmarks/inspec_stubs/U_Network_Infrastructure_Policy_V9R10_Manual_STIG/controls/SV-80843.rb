control 'SV-80843' do
  title 'Multi-Protocol Labeled Switching (MPLS) protocols deployed to build Label-Switch Path (LSP) tunnels must authenticate all messages with a hash function using the most secured cryptographic algorithm available.'
  desc 'Spoofed TCP segments could be introduced into the connection streams for LDP sessions used to build LSPs. By configuring strict authentication between LSR peers, LDP TCP sessions can be restricted and the integrity of LSPs can be guarded using the TCP MD5 Signature Option. The LSR ignores LDP Hellos from any LSR for which a password has not been configured. This ensures that the LSR establishes LDP TCP connections only with LSRs for which the shared secret has been configured. RSVP messages are used to control resource reservations for MPLS TE tunnels inside the MPLS core. The RSVP message authentication permits neighbors to use a secure hash to digitally sign all RSVP signaling messages, thus allowing the receiver of an RSVP message to verify the sender. By protecting against corruption and spoofing of RSVP messages, the integrity of the LSPs for bandwidth provisioning, path setup, and path teardown is maintained.'
  desc 'check', 'Review the router configuration to determine if LDP and RSVP messages are being authenticated as shown in the examples below.

If authentication is not being used for these protocols using a secured hashing algorithm for message authentication, this is a finding.

An LDP session is secured by configuring a password for each LDP peer as shown in the example below:

mpls ip
mpls label protocol ldp
mpls ldp neighbor 10.1.1.1 password xzxxxxxxxxxxx 
mpls ldp neighbor 10.3.3.3 password xxxxxzzzzxxxz

The IP address 10.1.1.1 and 10.3.3.3 in this example are the router IDs of the neighbors for which this router has an LDP session requiring MD5 authentication. To specify that the router ID 10.1.1.1 is to be found in VPN routing/forwarding instance (VRF) named VPN1 instead of the global route table, the "vrf" keyword is used in the command as shown in the following example:

mpls ldp neighbor vrf VPN1 10.1.1.1 password xxxxxxxxxxxxxxxxx

A group of peers using the same MD5 password can be configured as shown in the example below: 

mpls ldp password for 10 xxxxxxxxxxxxxxx
mpls ldp password required for 10
!
access-list 10 permit 10.1.1.1
access-list 10 permit 10.3.3.3
access-list 10 permit 10.4.4.4

The access list specifies a password is mandatory for LDP sessions with neighbors whose LDP router IDs are permitted by the access list.

To configure MD5 or SHA-1 authentication for RSVP, both ip rsvp authentication key and ip rsvp authentication commands must be configured as shown in the example below. The latter command simply enables authentication.

interface Ethernet0/0
ip address 192.168.101.2 255.255.255.0
ip rsvp bandwidth 7500 7500
ip rsvp authentication type sha-1
ip rsvp authentication key xxxxxxxx ip rsvp authentication

Note: If SHA-1 is not specified using the ip rsvp authentication type command, MD5 will be utilized.'
  desc 'fix', 'Implement neighbor authentication using a secured hashing algorithm for all signaling protocols deployed to build LSP tunnels.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-66999r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66353'
  tag rid: 'SV-80843r1_rule'
  tag stig_id: 'NET2000'
  tag gtitle: 'NET2000'
  tag fix_id: 'F-72429r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
