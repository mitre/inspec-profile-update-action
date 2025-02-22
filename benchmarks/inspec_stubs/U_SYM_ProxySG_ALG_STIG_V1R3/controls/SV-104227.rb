control 'SV-104227' do
  title 'Symantec ProxySG must be configured to remove or disable unrelated or unneeded application proxy services.'
  desc 'Unrelated or unneeded proxy services increase the attack vector and add excessive complexity to the securing of the ALG. Multiple application proxies can be installed on many ALGs. However, proxy types must be limited to related functions. At a minimum, the web and email gateway represent different security domains/trust levels. Organizations should also consider separation of gateways that service the DMZ and the trusted network.

Possible services that may be configured on the ProxySG:
AOL IM
DNS Proxy
FTP
FTPS
HTTPS
HTTPS Reverse Proxy
MMS
MSN IM
RMTP
RTSP
SOCKS
TLS
TCP Tunnel
TELNET
Yahoo IM'
  desc 'check', 'Determine what proxy services are enabled on the ProxySG.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Review each service specified in the list with the ProxySG administrator to verify that each is required.

If Symantec ProxySG is not configured to remove or disable unrelated or unneeded application proxy services, this is a finding.'
  desc 'fix', 'Disable/remove unnecessary proxy services on the ProxySG. In particular, reverse proxy services should not configured if not used.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Review each service and service group specified in the list with the ProxySG administrator.
4. Remove any unnecessary services or service groups by selecting them and clicking "delete".
5. Click "Apply" once all unnecessary services or groups have been removed.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93459r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94273'
  tag rid: 'SV-104227r1_rule'
  tag stig_id: 'SYMP-AG-000290'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-100389r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
