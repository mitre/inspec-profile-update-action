control 'SV-233293' do
  title 'The Juniper router must not be configured to use IPv6 Site Local Unicast addresses.'
  desc 'As currently defined, site local addresses are ambiguous and can be present in multiple sites. The address itself does not contain any indication of the site to which it belongs. The use of site-local addresses has the potential to adversely affect network security through leaks, ambiguity, and potential misrouting as documented in section 2 of RFC3879. RFC3879 formally deprecates the IPv6 site-local unicast prefix FEC0::/10 as defined in RFC3513.'
  desc 'check', 'Review the router configuration to ensure FEC0::/10 IP addresses are not defined. 

If FEC0::/10 IP addresses are defined, this is a finding.'
  desc 'fix', 'Configure the device using authorized IPv6 addresses.'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-36227r639643_chk'
  tag severity: 'medium'
  tag gid: 'V-233293'
  tag rid: 'SV-233293r639663_rule'
  tag stig_id: 'JUNI-RT-000235'
  tag gtitle: 'SRG-NET-000512-RTR-000013'
  tag fix_id: 'F-36195r622156_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
