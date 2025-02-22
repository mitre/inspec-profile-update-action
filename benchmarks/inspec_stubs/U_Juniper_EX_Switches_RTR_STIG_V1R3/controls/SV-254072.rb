control 'SV-254072' do
  title 'The Juniper router must not be configured to use IPv6 Site Local Unicast addresses.'
  desc 'As currently defined, site local addresses are ambiguous and can be present in multiple sites. The address itself does not contain any indication of the site to which it belongs. The use of site-local addresses has the potential to adversely affect network security through leaks, ambiguity, and potential misrouting as documented in section 2 of RFC3879. RFC3879 formally deprecates the IPv6 site-local unicast prefix FEC0::/10 as defined in RFC3513.'
  desc 'check', %q(Review the router configuration to ensure FEC0::/10 IP addresses are not defined. 

Show the interface configuration using "show configuration interfaces" (from operational mode) or "show interfaces" (configuration mode at the top of the hierarchy).

When showing the configuration, piping (|) to match or find (similar to *nix 'grep') will limit the search.

For example, to limit the search to lines that include "FEC0":
(operational mode) show configuration interfaces | match fec0
  Returns the lines with 'fec0' but no surrounding context
  There should be no returned lines

(operational mode) show configuration interfaces | find fec0
  Returns the configuration with the first line containing 'fec0'
  Returns context (meaning can scroll up / down in the configuration)
  There should be no returned configuration

If IPv6 Site Local Unicast addresses are defined, this is a finding.)
  desc 'fix', 'Configure the router using authorized IPv6 addresses.

Delete unauthorized addresses:
delete interfaces <interface name> unit <logical unit number> family inet6 address <unauth address>/<prefix>

Configure authorized addresses:
set interfaces <interface name> unit <logical unit number> family inet6 address <auth address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57524r844247_chk'
  tag severity: 'medium'
  tag gid: 'V-254072'
  tag rid: 'SV-254072r844249_rule'
  tag stig_id: 'JUEX-RT-001000'
  tag gtitle: 'SRG-NET-000512-RTR-000013'
  tag fix_id: 'F-57475r844248_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
