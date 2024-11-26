control 'SV-205242' do
  title 'The DNS implementation must implement internal/external role separation.'
  desc 'DNS servers with an internal role only process name/address resolution requests from within the organization (i.e., internal clients). DNS servers with an external role only process name/address resolution information requests from clients external to the organization (i.e., on the external networks, including the Internet). The set of clients that can access an authoritative DNS server in a particular role is specified by the organization using address ranges, explicit access control lists, etc. In order to protect internal DNS resource information, it is important to isolate the requests to internal DNS servers. Separating internal and external roles in DNS prevents address space that is private (e.g., 10.0.0.0/24) or is otherwise concealed by some form of Network Address Translation from leaking into the public DNS system.'
  desc 'check', 'Review the zone configuration with the DNS administrator and verify whether the zone has records on both the internal and external networks. If the zone is split, verify there is a separate external name server to handle the host records for external address space and an internal name server to handle the host records for internal address space.

If there are split zones and there are not internal and external roles to protect private address space, this is a finding.'
  desc 'fix', 'Configure the DNS server to separate internal and external roles to protect private address space.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5509r392639_chk'
  tag severity: 'medium'
  tag gid: 'V-205242'
  tag rid: 'SV-205242r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000101'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5509r392640_fix'
  tag 'documentable'
  tag legacy: ['SV-69191', 'V-54945']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
