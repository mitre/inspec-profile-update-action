control 'SV-215577' do
  title 'The Windows 2012 DNS Server must implement cryptographic mechanisms to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).'
  desc 'Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes.

Confidentiality is not an objective of DNS, but integrity is. DNSSEC and TSIG/SIG(0) both digitally sign DNS information to authenticate its source and ensure its integrity.'
  desc 'check', 'Note: This requirement applies to any Windows DNS Server which host non-AD-integrated zones even if the DNS servers host AD-integrated zones, too. If the Windows DNS Server only hosts AD-integrated zones and does not host any file-based zones, this is not applicable.
Validate this check from the Windows 2012 DNS server being configured/reviewed.

Note: This requirement does not apply for classified environments.

Log on to the Windows 2012 DNS server using the account designated as Administrator or DNS Administrator.
Determine a valid host in the zone.

Open the Windows PowerShell prompt on the Windows 2012 DNS server being configured/reviewed.

Issue the following command:
(Replace www.zonename.mil with a FQDN of a valid host in the zone being validated. Replace ###.###.###.### with the FQDN or IP address of the Windows 2012 DNS Server hosting the signed zone.)

resolve-dnsname www.zonename.mil -server ###.###.###.### -dnssecok <enter>

Note: It is important to use the -server switch followed by the DNS Server name/IP address.

The result should show the "A" record results.

In addition, the results should show QueryType: RRSIG with an expiration, date signed, signer and signature, similar to the following:

Name: www.zonename.mil
QueryType: RRSIG
TTL: 189
Section: Answer
TypeCovered: CNAME
Algorithm: 8
LabelCount: 3
OriginalTtl: 300
Expiration: 11/21/2014 10:22:28 PM
Signed: 10/22/2014 10:22:28 PM
Signer: zonename.mil
Signature: {87, 232, 34, 134...}

Name: origin-www.zonename.mil
QueryType: A
TTL: 201
Section: Answer
IP4Address: ###.###.###.###

If the results do not show the RRSIG and signature information, this is a finding.'
  desc 'fix', 'Sign, or re-sign, the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the account designated as Administrator or DNS Administrator.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click Sign the Zone, either using approved saved parameters or approved custom parameters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16771r314206_chk'
  tag severity: 'medium'
  tag gid: 'V-215577'
  tag rid: 'SV-215577r561297_rule'
  tag stig_id: 'WDNS-CM-000007'
  tag gtitle: 'SRG-APP-000440-DNS-000065'
  tag fix_id: 'F-16769r314207_fix'
  tag 'documentable'
  tag legacy: ['SV-73017', 'V-58587']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
