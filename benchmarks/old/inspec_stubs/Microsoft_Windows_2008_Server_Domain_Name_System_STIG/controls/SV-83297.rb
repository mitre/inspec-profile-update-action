control 'SV-83297' do
  title 'When IPv6 protocol is installed, the server must also be configured to answer for IPv6 AAAA records.'
  desc 'To prevent the possibility of a denial of service in relation to an IPv4 DNS server trying to respond to IPv6 requests, the server should be configured not to listen on any of its IPv6 interfaces unless it does contain IPv6 AAAA resource records in one of the zones.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

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
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59499r4_chk'
  tag severity: 'medium'
  tag gid: 'V-58627'
  tag rid: 'SV-83297r3_rule'
  tag stig_id: 'WDNS-CM-000028'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-64011r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
