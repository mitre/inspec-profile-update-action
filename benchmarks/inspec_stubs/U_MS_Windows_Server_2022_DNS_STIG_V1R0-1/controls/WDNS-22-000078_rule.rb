control 'WDNS-22-000078_rule' do
  title 'The Windows 2022 DNS Server must verify the correct operation of security functions upon startup and/or restart, upon command by a user with privileged access, and/or every 30 days.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Without verification, security functions may not operate correctly, and this failure may go unnoticed. 

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

The DNS server should perform self-tests, such as at server startup, to confirm that its security functions are working properly.'
  desc 'check', 'Note: This requirement applies to any Windows DNS Server that hosts non-Active Directory (AD)-integrated zones even if the DNS servers host AD-integrated zones, too. If the Windows DNS Server hosts only AD-integrated zones and does not host any file-based zones, this is not applicable.

Validate this check from the Windows 2022 DNS Server being configured/reviewed.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Determine a valid host in the zone.

Open the Windows PowerShell prompt on the Windows 2022 DNS Server being configured/reviewed.

Issue the following command:
(Replace www.zonename.mil with a FQDN of a valid host in the zone being validated. Replace ###.###.###.### with the FQDN or IP address of the Windows 2022 DNS Server hosting the signed zone.)

resolve-dnsname www.zonename.mil -server ###.###.###.### -dnssecok <enter>

Note: It is important to use the -server switch followed by the DNS server name/IP address.

The result should show the "A" record results.

In addition, the results should show QueryType: RRSIG with an expiration, date signed, signer, and signature, similar to the following:

Name: www.zonename.mil
QueryType: RRSIG
TTL: 189
Section: Answer
TypeCovered: CNAME
Algorithm: 8
LabelCount: 3
OriginalTtl: 300
Expiration: 11/21/2022 10:22:28 AM
Signed: 10/22/2022 10:22:28 AM
Signer: zonename.mil
Signature: {87, 232, 34, 134...}

Name: origin-www.zonename.mil
QueryType: A
TTL: 201
Section: Answer
IP4Address: ###.###.###.###

If the results do not show the RRSIG and signature information, this is a finding.'
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones". 

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either approved saved parameters or approved custom parameters.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000078_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000078'
  tag rid: 'WDNS-22-000078_rule'
  tag stig_id: 'WDNS-22-000078'
  tag gtitle: 'SRG-APP-000473-DNS-000072'
  tag fix_id: 'F-WDNS-22-000078_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
