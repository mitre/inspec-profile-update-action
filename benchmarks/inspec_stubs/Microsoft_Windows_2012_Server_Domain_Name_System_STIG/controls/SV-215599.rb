control 'SV-215599' do
  title 'The Windows 2012 DNS Server must require devices to re-authenticate for each dynamic update request connection attempt.'
  desc 'Without re-authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of devices, including, but not limited to, the following other situations:
(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) After a fixed period of time; or
(v) Periodically.

DNS does perform server authentication when DNSSEC or TSIG/SIG(0) are used, but this authentication is transactional in nature (each transaction has its own authentication performed). So this requirement is applicable for every server-to-server transaction request.'
  desc 'check', %q(Authentication of dynamic updates is accomplished in Windows Server 2012 DNS by configuring the zones to only accept secure dynamic updates.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Once selected, right-click the name of the zone, and from the displayed context menu, go to Properties.

On the opened domain's properties box, click the General tab.

Verify the Type: is Active Directory-Integrated.

Verify the Dynamic updates has "Secure only" selected.

If the zone is Active Directory-Integrated and the Dynamic updates are not configured for "Secure only", this is a finding.)
  desc 'fix', %q(Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Once selected, right-click the name of the zone, and from the displayed context menu, go to Properties.

On the opened domain's properties box, click the General tab.

If the Type: is not Active Directory-Integrated, configure the zone for AD-integration.

Select "Secure only" from the Dynamic updates: drop-down list.)
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16793r572239_chk'
  tag severity: 'medium'
  tag gid: 'V-215599'
  tag rid: 'SV-215599r561297_rule'
  tag stig_id: 'WDNS-IA-000001'
  tag gtitle: 'SRG-APP-000390-DNS-000048'
  tag fix_id: 'F-16791r572240_fix'
  tag 'documentable'
  tag legacy: ['SV-73061', 'V-58631']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
