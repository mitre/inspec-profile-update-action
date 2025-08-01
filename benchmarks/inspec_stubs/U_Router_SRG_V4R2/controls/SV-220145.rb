control 'SV-220145' do
  title 'The router must not be configured to use IPv6 Site Local Unicast addresses.'
  desc 'As currently defined, site local addresses are ambiguous and can be present in multiple sites. The address itself does not contain any indication of the site to which it belongs. The use of site-local addresses has the potential to adversely affect network security through leaks, ambiguity, and potential misrouting as documented in section 2 of RFC3879. RFC3879 formally deprecates the IPv6 site-local unicast prefix FEC0::/10 as defined in RFC3513.'
  desc 'check', 'Review the router configuration to ensure FEC0::/10 IP addresses are not defined. 

If IPv6 Site Local Unicast addresses are defined, this is a finding.'
  desc 'fix', 'Configure the router using authorized IPv6 addresses.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21860r457762_chk'
  tag severity: 'medium'
  tag gid: 'V-220145'
  tag rid: 'SV-220145r604135_rule'
  tag stig_id: 'SRG-NET-000512-RTR-000013'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-21852r539651_fix'
  tag 'documentable'
  tag legacy: ['V-101085', 'SV-110189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
