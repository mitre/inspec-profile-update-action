control 'WDNS-22-000054_rule' do
  title 'The Windows 2022 DNS Server must be configured to validate an authentication chain of parent and child domains via response data.'
  desc %q(If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down. 

Like the DNSKEY resource record, the DS Resource Record (RR) can be used to create a trust anchor for a signed zone. The DS record is smaller in size than a DNSKEY record because it contains only a hash of the public key.

The DS record is not added to a zone during the signing process like some DNSSEC-related RRs, even if a delegation already exists in the zone. To add a DS record, it must be manually added or imported. Fortunately, the DS resource record set (DSSET) is automatically added as a file to the Key Primary when a zone is signed. The DSSET file can be used with the "Import-DnsServerResourceRecordDS" cmdlet to import DS records to the parent zone.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS, to map between host/service names and network addresses, must provide other means to ensure the authenticity and integrity of response data.

DNSSEC provides the means to verify integrity assurances for the host/service name to network address resolution information obtained through the service. By using the DS RRs in the DNS, the security status of a child domain can be validated. The DS RR is used to identify the DNSSEC signing key of a delegated zone.

Starting from a trusted name server (such as the root name server) and down to the current source of response through successive verifications of signature of the public key of a child by its parent, the chain of trust is established. The public key of the trusted name servers is called the trust anchor. 

After authenticating the source, the next process DNSSEC calls for is to authenticate the response. This requires that responses consist of not only the requested RRs but also an authenticator associated with them. In DNSSEC, this authenticator is the digital signature of an RRSet. The digital signature of an RRSet is encapsulated through a special RRType called RRSIG. The DNS client using the trusted public key of the source (whose trust has just been established) then verifies the digital signature to detect if the response is valid or bogus.

This control enables the DNS to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service. Without indication of the security status of a child domain and enabling verification of a chain of trust, integrity and availability of the DNS infrastructure cannot be ensured.)
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

Validate this check from the Windows 2022 DNS Server being configured/reviewed.

Log on to the Windows 2022 DNS Server using the account designated as Administrator or DNS Administrator.

Determine a valid host in the zone.

Open the Windows PowerShell prompt on the Windows 2022 DNS Server being configured/reviewed.

Issue the following command:

PS C:\\> Get-DnsServerResourceRecord -ZoneName adatum.com -RRType DS

Replace "adatum.com" with the parent zone on the DNS server being evaluated.

HostName RecordType Timestamp TimeToLive RecordData
-------- ---------- --------- ---------- ----------
corp DS 0 01:00:00 [58555][Sha1][RsaSha1NSec3]
corp DS 0 01:00:00 [58555][Sha256][RsaSha1NSec3]
corp DS 0 01:00:00 [63513][Sha1][RsaSha1NSec3]
corp DS 0 01:00:00 [63513][Sha256][RsaSha1NSec3]

If the results do not show the DS records for the child domain(s), this is a finding.

In the previous example, DS records for the child zone, corp.adatum.com, were imported into the parent zone, adatum.com, by using the DSSET file in the c:\\windows\\system32\\dns directory. The DSSET file was located in this directory because the local DNS server is the Key primary for the child zone.

If the Key Master DNS server for a child zone is not the same computer as the primary authoritative DNS server for the parent zone where the DS record is being added, the DSSET file must be obtained for the child zone and made available to the primary authoritative server for the parent zone. Alternatively, the DS records can be added manually.'
  desc 'fix', 'A DS record must be added manually or imported.

The DSSET is automatically added as a file to the Key primary when a zone is signed. 

This file can be used with the "Import-DnsServerResourceRecordDS" cmdlet to import DS records to the parent zone.

Example:
PS C:\\> Import-DnsServerResourceRecordDS -ZoneName adatum.com -DSSetFile "c:\\windows\\system32\\dns\\dsset-corp.adatum.com"'
  impact 0.5
  tag check_id: 'C-WDNS-22-000054_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000054'
  tag rid: 'WDNS-22-000054_rule'
  tag stig_id: 'WDNS-22-000054'
  tag gtitle: 'SRG-APP-000215-DNS-000026'
  tag fix_id: 'F-WDNS-22-000054_fix'
  tag 'documentable'
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
