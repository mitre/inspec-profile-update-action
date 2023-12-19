control 'WDNS-22-000120_rule' do
  title 'Windows 2022 DNS response rate limiting (RRL) must be enabled.'
  desc 'This setting can prevent someone from sending a denial-of-service attack using the DNS servers. For instance, a bot net can send requests to the DNS server using the IP address of a third computer as the requestor. Without RRL, the DNS servers might respond to all the requests, flooding the third computer.'
  desc 'check', 'As an administrator, run PowerShell and enter the following command: 
"Get-DnsServerResponseRateLimiting". 

If "Mode" is not set to "Enable", this is a finding.'
  desc 'fix', 'As an administrator, run PowerShell and enter the command "Set-DnsServerResponseRateLimiting" to apply default values or "Set-DnsServerResponseRateLimiting -WindowInSec 7 -LeakRate 4 -TruncateRate 3 -ErrorsPerSec 8 -ResponsesPerSec 8". 

These settings are just an example. For more information, go to:
https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverresponseratelimiting?view=windowsserver2022-ps'
  impact 0.5
  tag check_id: 'C-WDNS-22-000120_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000120'
  tag rid: 'WDNS-22-000120_rule'
  tag stig_id: 'WDNS-22-000120'
  tag gtitle: 'SRG-APP-000247-DNS-000036'
  tag fix_id: 'F-WDNS-22-000120_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
