control 'SV-215611' do
  title 'The Windows 2012 DNS Servers IP address must be statically defined and configured locally on the server.'
  desc 'The major threat associated with DNS forged responses or failures are the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. By requiring remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service, data origin is validated. 

Ensuring all name servers have static IP addresses makes it possible to configure restricted DNS communication, such as with DNSSEC, between the name servers.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Locate the “Network Internet Access” icon, right-click on it and select "Open Network & Sharing Center".

Click on "Change adapter settings".

Right-click on the Ethernet and click “Properties”.

Select Internet Protocol Version 4 (TCP/IPv4) and click “Properties”.

Verify the “Use the following IP address” is selected, with an IP address, subnet mask, and default gateway assigned.

If the “Use the following IP address” is not selected with a configured IP address, subnet mask, and default gateway, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Locate the “Network Internet Access” icon, right-click on it and select "Open Network & Sharing Center".

Click on "Change adapter settings".

Right-click on the Ethernet and click “Properties”.

Select Internet Protocol Version 4 (TCP/IPv4) and click “Properties”.

Select the “Use the following IP address” and populate with an IP address, subnet mask, and default gateway.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16805r572251_chk'
  tag severity: 'medium'
  tag gid: 'V-215611'
  tag rid: 'SV-215611r561297_rule'
  tag stig_id: 'WDNS-SC-000003'
  tag gtitle: 'SRG-APP-000420-DNS-000053'
  tag fix_id: 'F-16803r572252_fix'
  tag 'documentable'
  tag legacy: ['SV-73085', 'V-58655']
  tag cci: ['CCI-002463', 'CCI-000366']
  tag nist: ['SC-20 (2)', 'CM-6 b']
end
