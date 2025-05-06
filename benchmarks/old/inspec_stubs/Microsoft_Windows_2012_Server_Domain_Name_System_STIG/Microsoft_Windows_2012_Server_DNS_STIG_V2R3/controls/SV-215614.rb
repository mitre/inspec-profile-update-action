control 'SV-215614' do
  title 'WINS lookups must be disabled on the Windows 2012 DNS Server.'
  desc 'The major threat associated with DNS forged responses or failures is the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. By requiring remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service, data origin is validated.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS, to map between host/service names and network addresses, must provide other means to assure the authenticity and integrity of response data. 

In the case of DNS, employ DNSSEC to provide an additional data origin and integrity artifacts along with the authoritative data the system returns in response to DNS name/address resolution queries.

If/when WINS lookups are enabled, the validity of the data becomes questionable since the WINS data is provided to the requestor, unsigned and invalidated. In order to be assured only the DNSSEC-signed data is being returned, WINS lookups must be disabled.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, right-click each zone, and then click “Properties”.

In the “Properties” dialog box for the zone, click the “WINS” tab.

Verify the "Use WINS forward lookup" check box is not selected.

If the "Use WINS forward lookup" check box is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, right-click each zone, and then click “Properties”.

In the “Properties” dialog box for the zone, click the “WINS” tab.

Uncheck the "Use WINS forward" lookup check box.

Click “OK”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16808r572254_chk'
  tag severity: 'medium'
  tag gid: 'V-215614'
  tag rid: 'SV-215614r561297_rule'
  tag stig_id: 'WDNS-SC-000006'
  tag gtitle: 'SRG-APP-000422-DNS-000055'
  tag fix_id: 'F-16806r572255_fix'
  tag 'documentable'
  tag legacy: ['SV-73091', 'V-58661']
  tag cci: ['CCI-002462']
  tag nist: ['SC-20 a']
end
