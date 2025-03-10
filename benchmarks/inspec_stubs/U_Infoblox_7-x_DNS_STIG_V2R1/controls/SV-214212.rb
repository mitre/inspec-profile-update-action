control 'SV-214212' do
  title 'The DNS implementation must implement internal/external role separation.'
  desc 'DNS servers with an internal role only process name/address resolution requests from within the organization (i.e., internal clients). DNS servers with an external role only process name/address resolution information requests from clients external to the organization (i.e., on the external networks, including the Internet). The set of clients that can access an authoritative DNS server in a particular role is specified by the organization using address ranges, explicit access control lists, etc. In order to protect internal DNS resource information, it is important to isolate the requests to internal DNS servers. Separating internal and external roles in DNS prevents address space that is private (e.g., 10.0.0.0/24) or is otherwise concealed by some form of Network Address Translation from leaking into the public DNS system.'
  desc 'check', 'Review the Infoblox Grid configuration to verify that the appropriate zones are served by the correct internal or external member.
Review the usage of DNS views as necessary.

Navigate to Data Management >> DNS >> Members/Servers and Zones tabs.

Review each zone and member assignment to ensure it is configured correctly with respect to its network assignment.

If an external server contains internal data, or vice versa, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Members/Servers and Zones tabs.

Modify the zone name server assignment as necessary to ensure role separation.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15427r295899_chk'
  tag severity: 'medium'
  tag gid: 'V-214212'
  tag rid: 'SV-214212r612370_rule'
  tag stig_id: 'IDNS-7X-000840'
  tag gtitle: 'SRG-APP-000516-DNS-000101'
  tag fix_id: 'F-15425r295900_fix'
  tag 'documentable'
  tag legacy: ['SV-83137', 'V-68647']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
