control 'SV-237757' do
  title 'The Cisco switch must not be configured to use IPv6 Site Local Unicast addresses.'
  desc 'As currently defined, site local addresses are ambiguous and can be present in multiple sites. The address itself does not contain any indication of the site to which it belongs. The use of site-local addresses has the potential to adversely affect network security through leaks, ambiguity, and potential misrouting as documented in section 2 of RFC3879. RFC3879 formally deprecates the IPv6 site-local unicast prefix FEC0::/10 as defined in RFC3513.'
  desc 'check', 'Review the switch configuration to ensure FEC0::/10 IPv6 addresses are not defined. 

If IPv6 Site Local Unicast addresses are defined, this is a finding.'
  desc 'fix', 'Configure the switch using only authorized IPv6 addresses.'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-40973r648784_chk'
  tag severity: 'medium'
  tag gid: 'V-237757'
  tag rid: 'SV-237757r648788_rule'
  tag stig_id: 'CISC-RT-000237'
  tag gtitle: 'SRG-NET-000512-RTR-000013'
  tag fix_id: 'F-40935r648785_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
