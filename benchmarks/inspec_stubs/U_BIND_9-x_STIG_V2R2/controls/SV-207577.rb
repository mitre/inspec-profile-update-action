control 'SV-207577' do
  title 'A BIND 9.x server implementation must maintain the integrity and confidentiality of DNS information while it is being prepared for transmission, in transmission, and in use and t must perform integrity verification and data origin verification for all DNS information.'
  desc "DNSSEC is required for securing the DNS query/response transaction by providing data origin authentication and data integrity verification through signature verification and the chain of trust

Failure to accomplish data origin authentication and data integrity verification could have significant effects on DNS Infrastructure. The resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed that would result in query failure or denial of service

Failure to validate name server replies would cause many networking functions and communications to be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.

Failure to validate the chain of trust used with DNSSEC would have a significant impact on the security posture of the DNS server. Non-validated trust chains may contain rouge DNS servers and allow those unauthorized servers to introduce invalid data into an organizations DNS infrastructure. A compromise of this type would be difficult to detect and may have devastating effects on the validity and integrity of DNS zone information.

"
  desc 'check', 'If the server is in a classified network, this is Not Applicable.
If the server is forwarding all queries to the ERS, this is Not Applicable as the ERS validates.

Verify that DNSSEC is enabled.

Inspect the "named.conf" file for the following:

dnssec-enable yes;

If "dnssec-enable" does not exist or is not set to "yes", this is a finding.

Verify that each zone on the name server has been signed.

Identify each zone file that the name sever is responsible for and search each file for the "DNSKEY" entries:

# less <signed_zone_file>
86400 DNSKEY 257 3 8 ( HASHED_KEY ) ; KSK; alg = ECDSAP256SHA256; key id = 31225
86400 DNSKEY 256 3 8 ( HASHED_KEY ) ; ZSK; alg = ECDSAP256SHA256; key id = 52179

Ensure that there are separate "DNSKEY" entries for the "KSK" and the "ZSK"

If the "DNSKEY" entries are missing, the zone file is not signed.
If the zone files are not signed, this is a finding.'
  desc 'fix', 'Set the "dnssec-enable" option to yes.

Sign each zone file that the name server is responsible for.

Configure each zone the name server is responsible for to use a DNSSEC signed zone.'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7832r283785_chk'
  tag severity: 'high'
  tag gid: 'V-207577'
  tag rid: 'SV-207577r612253_rule'
  tag stig_id: 'BIND-9X-001200'
  tag gtitle: 'SRG-APP-000213-DNS-000024'
  tag fix_id: 'F-7832r283786_fix'
  tag satisfies: ['SRG-APP-000213-DNS-000024', 'SRG-APP-000215-DNS-000026', 'SRG-APP-000219-DNS-000028', 'SRG-APP-000219-DNS-000029', 'SRG-APP-000219-DNS-000030', 'SRG-APP-000347-DNS-000041', 'SRG-APP-000348-DNS-000042', 'SRG-APP-000349-DNS-000043', 'SRG-APP-000420-DNS-000053', 'SRG-APP-000421-DNS-000054', 'SRG-APP-000422-DNS-000055', 'SRG-APP-000423-DNS-000056', 'SRG-APP-000424-DNS-000057', 'SRG-APP-000425-DNS-000058', 'SRG-APP-000426-DNS-000059', 'SRG-APP-000441-DNS-000066', 'SRG-APP-000442-DNS-000067', 'SRG-APP-000516-DNS-000089']
  tag 'documentable'
  tag legacy: ['SV-87095', 'V-72471']
  tag cci: ['CCI-001178', 'CCI-001663', 'CCI-002420', 'CCI-001901', 'CCI-001902', 'CCI-001904', 'CCI-002462', 'CCI-002463', 'CCI-002464', 'CCI-002465', 'CCI-002466', 'CCI-002467', 'CCI-002468', 'CCI-002422', 'CCI-001184']
  tag nist: ['SC-20 a', 'SC-20 b', 'SC-8 (2)', 'AU-10 (1) (a)', 'AU-10 (1) (b)', 'AU-10 (2) (a)', 'SC-20 a', 'SC-20 (2)', 'SC-20 (2)', 'SC-21', 'SC-21', 'SC-21', 'SC-21', 'SC-8 (2)', 'SC-23']
end
