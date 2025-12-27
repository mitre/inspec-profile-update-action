control 'SV-214172' do
  title 'A DNS server implementation must provide the means to enable verification of a chain of trust among parent and child domains (if the child supports secure resolution services).'
  desc "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to assure the authenticity and integrity of response data.

DNSSEC provides the means to verify integrity assurances for the host/service name to network address resolution information obtained through the service. By using the delegation signer (DS) resource records in the DNS, the security status of a child domain can be validated. The DS resource record is used to identify the DNSSEC signing key of a delegated zone.

Starting from a trusted name server (such as the root name server) and down to the current source of response through successive verifications of signature of the public key of a child by its parent, the chain of trust is established. The public key of the trusted name servers is called the trust anchor. After authenticating the source, the next process DNSSEC calls for is to authenticate the response. This requires that responses consist of not only the requested RRs but also an authenticator associated with them. In DNSSEC, this authenticator is the digital signature of a Resource Record (RR) Set. The digital signature of an RRSet is encapsulated through a special RRType called RRSIG. The DNS client using the trusted public key of the source (whose trust has just been established) then verifies the digital signature to detect if the response is valid or bogus.

This control enables the DNS to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. Without indication of the security status of a child domain and enabling verification of a chain of trust, integrity and availability of the DNS infrastructure cannot be assured."
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Authoritative Check: Navigate to Data Management >> DNS >> Zones.

Ensure external authoritative zones are DNSSEC signed.

Recursive Check: Navigate to Data Management >> DNS >> Zones.

Note: DNSSEC validation is only applicable on a grid member where recursion is active.

Edit "Grid DNS Properties", toggle Advanced Mode, and select the DNSSEC tab.
Validate that both "Enable DNSSEC" and "Enable DNSSEC Validation" are enabled.
When complete, click "Cancel" to exit the "Properties" screen.

If DNSSEC is not utilized for authoritative DNS and recursive clients this is a finding.

Note: To add "Signed" column, select an existing column, select the down arrow, select "Columns", select "Edit Columns", select the check box for "Visible" and select "Apply".'
  desc 'fix', 'Authoritative Fix: Navigate to Data Management >> DNS >> Zones.

Select the appropriate zone using the check box, then use the "DNSSEC" drop-down menu and select "Sign Zones".
Follow prompt to acknowledge zone signing.

Recursive Fix: Navigate to Data Management >> DNS >> Zones.

Edit "Grid DNS Properties", toggle Advanced Mode, and select the "DNSSEC" tab.
Enable both "Enable DNSSEC" and "Enable DNSSEC Validation" options.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15387r295782_chk'
  tag severity: 'medium'
  tag gid: 'V-214172'
  tag rid: 'SV-214172r612370_rule'
  tag stig_id: 'IDNS-7X-000250'
  tag gtitle: 'SRG-APP-000215-DNS-000026'
  tag fix_id: 'F-15385r295783_fix'
  tag 'documentable'
  tag legacy: ['V-68539', 'SV-83029']
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
