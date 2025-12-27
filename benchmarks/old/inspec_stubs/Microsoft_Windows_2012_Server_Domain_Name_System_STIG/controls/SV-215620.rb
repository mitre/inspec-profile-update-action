control 'SV-215620' do
  title 'Trust anchors must be exported from authoritative Windows 2012 DNS Servers and distributed to validating Windows 2012 DNS Servers.'
  desc "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its sub domain, from the top of the DNS hierarchy down.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS, to map between host/service names and network addresses, must provide other means to assure the authenticity and integrity of response data.

DNSSEC provides the means to verify integrity assurances for the host/service name to network address resolution information obtained through the service. By using the delegation signer (DS) resource records in the DNS, the security status of a child domain can be validated.  The DS resource record is used to identify the DNSSEC signing key of a delegated zone.

Starting from a trusted name server (such as the root name server) and down to the current source of response through successive verifications of signature of the public key of a child by its parent, the chain of trust is established. The public key of the trusted name servers is called the trust anchor. After authenticating the source, the next process DNSSEC calls for is to authenticate the response. This requires that responses consist of not only the requested RRs but also an authenticator associated with them. In DNSSEC, this authenticator is the digital signature of a Resource Record (RR) Set. The digital signature of an RRSet is encapsulated through a special RRType called RRSIG. The DNS client using the trusted public key of the source (whose trust has just been established) then verifies the digital signature to detect if the response is valid or bogus.

This control enables the DNS to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service.  Without indication of the security status of a child domain and enabling verification of a chain of trust, integrity and availability of the DNS infrastructure cannot be assured.

A trust anchor is a preconfigured public key associated with a specific zone. A validating DNS server must be configured with one or more trust anchors in order to perform validation. If the DNS server is running on a domain controller, trust anchors are stored in the forest directory partition in Active Directory Domain Services (AD DS) and can be replicated to all domain controllers in the forest. On standalone DNS servers, trust anchors are stored in a file named TrustAnchors.dns. A DNS server running Windows Server 2012 or Windows Server 2012 R2 also displays configured trust anchors in the DNS Manager console tree in the Trust Points container. Trust anchors can also be viewed by executing Windows PowerShell commands or Dnscmd.exe at a Windows command prompt."
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Log onto each of the validating Windows 2012 DNS Servers.

In the DNS Manager console tree, navigate to each hosted zone under the Trust Points folder.

Two DNSKEY trust points should be displayed, one for the active key and one for the standby key.

If each validating Windows 2012 DNS Servers does not reflect the DNSKEY trust points for each of the hosted zone(s), this is a finding.'
  desc 'fix', 'Log onto the primary DNS server and click Windows Explorer on the taskbar.

Navigate to C:\\Windows\\System32, right-click the dns folder, point to Share with, and then click Advanced sharing.

In the dns Properties dialog box, click Advanced Sharing, select the Share this folder check box, verify the Share name is dns, and then click OK.

Click Close and then close Windows Explorer.

Log onto each of the validating Windows 2012 DNS Servers.

In the DNS Manager console tree, navigate to the Trust Points folder.

Right-click Trust Points, point to Import, and then click DNSKEY.

In the Import DNSKEY dialog box, type \\\\primaryhost\\dns\\keyset-domain.mil (where primaryhost represent the FQDN of the Primary DNS Server and domain.mil represents the zone(s)).

Click OK.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16814r314335_chk'
  tag severity: 'medium'
  tag gid: 'V-215620'
  tag rid: 'SV-215620r561297_rule'
  tag stig_id: 'WDNS-SC-000012'
  tag gtitle: 'SRG-APP-000215-DNS-000026'
  tag fix_id: 'F-16812r314336_fix'
  tag 'documentable'
  tag legacy: ['SV-73103', 'V-58673']
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
