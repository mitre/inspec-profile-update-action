control 'SV-215600' do
  title 'The Windows 2012 DNS Server must uniquely identify the other DNS server before responding to a server-to-server transaction.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. This applies to server-to-server (zone transfer) transactions only and is provided by TSIG/SIG(0), which enforces mutual server authentication using a key that is unique to each server pair (TSIG) or using PKI-based authentication (SIG(0)), thus uniquely identifying the other server.

TSIG and SIG(0) are not configurable in Windows 2012 DNS Server.

To meet the requirement for authentication between Windows DNS servers, IPsec will be implemented between the Windows DNS servers which host any non-AD-integrated zones.'
  desc 'check', 'Note: This requirement applies to any Windows DNS Server which host non-AD-integrated zones even if the DNS servers host AD-integrated zones, too.

If the Windows DNS Servers only host AD-integrated zones, this requirement is not applicable.

Log on to the DNS server which hosts non-AD-integrated zones using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute gpme.msc to open the Group Policy Management feature.

In the “Browse for Group Policy Object” dialog box, double-click “Domain Controllers.domain.com”.

Click “Default Domain Controllers Policy” and click “OK”.

In the console tree, open Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Firewall with Advanced Security\\Windows Firewall with Advanced Security - LDAP.

Click “Connection Security Rules”.

Confirm at least one rule is configured for TCP 53.

Double-click on each Rule to verify the following: 

On the “Authentication” tab, "Authentication mode:" is set to "Request authentication for inbound and outbound connections".

Confirm the "Signing Algorithm" is set to "RSA (default)".

On the “Remote Computers” tab, Endpoint1 and Endpoint2 are configured with the IP addresses of all DNS servers.

On the “Protocols and Ports” tab, "Protocol type:" is set to either TCP (depending upon which rule is being reviewed) and the "Endpoint 1 port:" is set to "Specific ports" and "53".

If there are not rules(s) configured with the specified requirements, this is a finding.'
  desc 'fix', %q(Complete the following procedures twice for each pair of name servers.

First create a rule for TCP connections.

Refer to the U_Windows_Domain_Name_Service_2008_Overview.pdf for Microsoft links for this procedure.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute gpme.msc to open the Group Policy Management feature.

In the Browse for “Group Policy Object” dialog box, double-click “Domain Controllers.domain.com”.

Click “Default Domain Controllers Policy” and click “OK”.

In the console tree, open Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security - LDAP.

Right-Click “Connection Security Rules” and select “New”.

For Rule Type, select the "Server-to-server" radio button, click “Next”.

For Endpoint 1 and Endpoint 2, select "These IP addresses:" and add the IP addresses of all DNS servers, click “Next”.

For Requirements, select "Request authentication for inbound and outbound connections", click “Next”.

For Authentication Method, select Computer certificate and from the "Signing Algorithm:" drop-down, select "RSA (default)".

From the "Certificate store type:" drop-down, select "Root CA (default)”.

From the "CA name:", click “Browse” and select the certificate for the CA, click “Next”.

On Profile, accept default selections, click “Next”.

On Name, enter a name applicable to the rule's function, click “Finish”.)
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16794r572242_chk'
  tag severity: 'medium'
  tag gid: 'V-215600'
  tag rid: 'SV-215600r561297_rule'
  tag stig_id: 'WDNS-IA-000002'
  tag gtitle: 'SRG-APP-000158-DNS-000015'
  tag fix_id: 'F-16792r572243_fix'
  tag 'documentable'
  tag legacy: ['SV-73063', 'V-58633']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
