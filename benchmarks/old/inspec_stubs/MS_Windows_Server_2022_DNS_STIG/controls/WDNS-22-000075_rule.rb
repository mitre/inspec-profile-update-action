control 'WDNS-22-000075_rule' do
  title 'The DNS Name Server software must be configured to refuse queries for its version information.'
  desc 'Each newer version of the name server software, especially the BIND software, generally is devoid of vulnerabilities found in earlier versions because it has design changes incorporated to address those vulnerabilities. The vulnerabilities have been exploited (i.e., some form of attack was launched), and sufficient information has been generated with respect to the nature of those exploits. It makes good business sense to run the latest version of name server software because theoretically it is the safest version.

In some installations, it may not be possible to switch to the latest version of name server software immediately. If the version of the name server software is revealed in queries, this information may be used by attackers looking for a specific version of the software that has a discovered weakness. To prevent information about which version of name server software is running on a system, name servers should be configured to refuse queries for its version information.'
  desc 'check', 'The "EnableVersionQuery" property controls what version information the DNS server will respond with when a DNS query with class set to "CHAOS" and type set to "TXT" is received.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Open a command window and execute the command:

nslookup <enter>
Note: Confirm the Default Server is the DNS server on which the command is being run.

At the nslookup prompt, type:

set type=TXT <enter>
set class=CHAOS <enter>
version.bind <enter>

If the response returns something similar to text = "Microsoft DNS 6.1.7601 (1DB14556)", this is a finding.'
  desc 'fix', 'To disable the version being returned in queries, execute the following command:

dnscmd /config /EnableVersionQuery 0 <enter>'
  impact 0.5
  tag check_id: 'C-WDNS-22-000075_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000075'
  tag rid: 'WDNS-22-000075_rule'
  tag stig_id: 'WDNS-22-000075'
  tag gtitle: 'SRG-APP-000333-DNS-000104'
  tag fix_id: 'F-WDNS-22-000075_fix'
  tag 'documentable'
  tag cci: ['CCI-002201']
  tag nist: ['AC-4 (12)']
end
