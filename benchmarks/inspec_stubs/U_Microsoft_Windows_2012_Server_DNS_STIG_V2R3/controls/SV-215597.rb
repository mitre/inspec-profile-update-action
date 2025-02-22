control 'SV-215597' do
  title 'IPv6 protocol must be disabled unless the Windows 2012 DNS server is configured to answer for and hosting IPv6 AAAA records.'
  desc 'To prevent the possibility of a denial of service in relation to an IPv4 DNS server trying to respond to IPv6 requests, the server should be configured not to listen on any of its IPv6 interfaces unless it does contain IPv6 AAAA resource records in one of the zones.'
  desc 'check', 'Note: If the Windows 2012 DNS server is hosting IPv6 records, this requirement is not applicable. If the Windows 2012 DNS server is only hosting IPv4 records, this requirement must be met.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

From a command prompt, run regedit. 
In the User Account Control dialog box, click Continue. 
In Registry Editor, locate and then click the following registry subkey: 
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters \\
Verify the value for “DisabledComponents” is “255 (0xff)”.

If the “DisabledComponents” entry is nonexistent, this is a finding.

If the “DisabledComponents” exists but is not set to “255 (0xff)”, and the DNS server is not hosting any AAAA records, this is a finding.'
  desc 'fix', 'Log onto the DNS server.

Access Group Policy Management.

Edit Default Domain Policy, go to Computer Configuration >> Policies >> Administrative Templates >> Network >> IPv6 Configuration, Open IPv6 Configuration Policy and set on “Disable all IPv6 components”.

As an alternative to using the GPO setting, the registry setting may also be altered directly to reflect:
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters \\
Set the value for “DisabledComponents” to “255 (0xff)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16791r572236_chk'
  tag severity: 'medium'
  tag gid: 'V-215597'
  tag rid: 'SV-215597r561297_rule'
  tag stig_id: 'WDNS-CM-000028'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-16789r572237_fix'
  tag 'documentable'
  tag legacy: ['SV-73057', 'V-58627']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
