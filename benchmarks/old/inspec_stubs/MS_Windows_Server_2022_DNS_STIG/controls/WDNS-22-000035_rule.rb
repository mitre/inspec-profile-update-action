control 'WDNS-22-000035_rule' do
  title 'The Windows 2022 DNS Server must uniquely identify the other DNS server before responding to a server-to-server transaction.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. This applies to server-to-server (zone transfer) transactions only and is provided by TSIG/SIG(0), which enforces mutual server authentication using a key that is unique to each server pair, TSIG, or using PKI-based authentication, SIG(0), thus uniquely identifying the other server.

TSIG and SIG(0) are not configurable in Windows 2022 DNS Server.

To meet the requirement for authentication between Windows DNS Servers, IPsec will be implemented between the Windows DNS Servers that host any non-Active Directory (AD)-integrated zones.'
  desc 'check', 'Note: This requirement applies to any Windows DNS Server that hosts non-AD-integrated zones, even if the DNS servers host AD-integrated zones, too.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "gpme.msc" to open the Group Policy Management feature.

In the "Browse for Group Policy Object" dialog box, double-click "Domain Controllers.domain.com".

Click "Default Domain Controllers Policy" and click "OK".

In the console tree, open Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Firewall with Advanced Security\\Windows Firewall with Advanced Security - LDAP.

Click "Connection Security Rules".

Confirm at least one rule is configured for TCP 53.

Double-click on each rule to verify the following: 

On the "Authentication" tab, "Authentication mode:" is set to "Request authentication for inbound and outbound connections".

The "Signing Algorithm" is set to "RSA (default)".

On the "Remote Computers" tab, "Endpoint1" and "Endpoint2" are configured with the IP addresses of all DNS servers.

On the "Protocols and Ports" tab, "Protocol type:" is set to either TCP (depending on which rule is being reviewed) and the "Endpoint 1 port:" is set to "Specific ports" and "53".

If no rules are configured with the specified requirements, this is a finding.'
  desc 'fix', %q(Complete the following procedures twice for each pair of name servers.

Create a rule for TCP connections.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "gpme.msc" to open the Group Policy Management feature.

In the "Browse for Group Policy Object" dialog box, double-click "Domain Controllers.domain.com".

Click "Default Domain Controllers Policy" and click "OK".

In the console tree, open Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security - LDAP.

Right-click "Connection Security Rules" and select "New".

For "Rule Type", select the "Server-to-server" radio button and click "Next".

For Endpoint 1 and Endpoint 2, select "These IP addresses:" and add the IP addresses of all DNS servers. Click "Next".

For "Requirements", select "Request authentication for inbound and outbound connections" and click "Next".

For "Authentication Method", select Computer certificate and from the "Signing Algorithm:" drop-down, select "RSA (default)".

From the "Certificate store type:" drop-down, select "Root CA (default)".

From the "CA name:", click "Browse", select the certificate for the CA, and click "Next".

On "Profile", accept default selections and click "Next".

On "Name", enter a name applicable to the rule's function.

Click "Finish".)
  impact 0.5
  tag check_id: 'C-WDNS-22-000035_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000035'
  tag rid: 'WDNS-22-000035_rule'
  tag stig_id: 'WDNS-22-000035'
  tag gtitle: 'SRG-APP-000158-DNS-000015'
  tag fix_id: 'F-WDNS-22-000035_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
