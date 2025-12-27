control 'WDNS-22-000046_rule' do
  title "The Windows 2022 DNS Server's IP address must be statically defined and configured locally on the server."
  desc 'The major threat associated with DNS forged responses or failures is the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. By requiring remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service, data origin is validated. 

Ensuring all name servers have static IP addresses makes it possible to configure restricted DNS communication, such as with DNSSEC, between the name servers.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Locate the "Network Internet Access" icon, right-click on it, and select "Open Network & Sharing Center".

Click "Change adapter settings".

Right-click on the Ethernet and click "Properties".

Select "Internet Protocol Version 4 (TCP/IPv4)" and click "Properties".

Verify the "Use the following IP address" is selected, with an IP address, subnet mask, and default gateway assigned.

If the "Use the following IP address" is not selected with a configured IP address, subnet mask, and default gateway, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Locate the "Network Internet Access" icon, right-click on it, and select "Open Network & Sharing Center".

Click "Change adapter settings".

Right-click on the Ethernet and click "Properties".

Select "Internet Protocol Version 4 (TCP/IPv4)" and click "Properties".

Select "Use the following IP address" and populate with an IP address, subnet mask, and default gateway.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000046_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000046'
  tag rid: 'WDNS-22-000046_rule'
  tag stig_id: 'WDNS-22-000046'
  tag gtitle: 'SRG-APP-000420-DNS-000053'
  tag fix_id: 'F-WDNS-22-000046_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002463']
  tag nist: ['CM-6 b', 'SC-20 (2)']
end
