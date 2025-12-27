control 'SV-256058' do
  title 'The Arista router must not be configured to use IPv6 Site Local Unicast addresses.'
  desc 'As currently defined, site local addresses are ambiguous and can be present in multiple sites. The address itself does not contain any indication of the site to which it belongs. The use of site-local addresses has the potential to adversely affect network security through leaks, ambiguity, and potential misrouting as documented in section 2 of RFC3879. RFC3879 formally deprecates the IPv6 site-local unicast prefix FEC0::/10 as defined in RFC3513.'
  desc 'check', 'Review the Arista router configuration to ensure FEC0::/10 IP addresses are not defined. 

Step 1: Verify that FECO::/10 IPv6 addresses are not configured.

interface ethernet 3
 no routerport 
 ipv6 address FD6D:8D64:AF0C:2::/64

If IPv6 Site Local Unicast addresses are defined, this is a finding.'
  desc 'fix', 'Configure the Arista router using authorized IPv6 addresses.

Step 1: Configure the interface with IPv6 address.

LEAF-1A(config-if-Et3)#interface ethernet 3
LEAF-1A(config-if-Et3)#no routerport 
LEAF-1A(config-if-Et3)#ipv6 address FD6D:8D64:AF0C:2::/64'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59734r882514_chk'
  tag severity: 'medium'
  tag gid: 'V-256058'
  tag rid: 'SV-256058r882516_rule'
  tag stig_id: 'ARST-RT-000790'
  tag gtitle: 'SRG-NET-000512-RTR-000013'
  tag fix_id: 'F-59677r882515_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
