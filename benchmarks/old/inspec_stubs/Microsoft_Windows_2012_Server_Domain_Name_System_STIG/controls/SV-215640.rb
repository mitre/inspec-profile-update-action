control 'SV-215640' do
  title 'The DNS Name Server software must be configured to refuse queries for its version information.'
  desc 'Each newer version of the name server software, especially the BIND software, generally is devoid of vulnerabilities found in earlier versions because it has design changes incorporated to take care of those vulnerabilities. Of course, these vulnerabilities have been exploited (i.e., some form of attack was launched), and sufficient information has been generated with respect to the nature of those exploits. Thus, it makes good business sense to run the latest version of name server software because theoretically it is the safest version.

In some installations, it may not be possible to switch over to the latest version of name server software immediately. If the version of the name server software is revealed in queries, this information may be used by attackers who are looking for a specific version of the software which has a discovered weakness. To prevent information about which version of name server software is running on a system, name servers should be configured to refuse queries for its version information.'
  desc 'check', 'The "EnableVersionQuery" property controls what version information the DNS server will respond with when a DNS query with class set to “CHAOS” and type set to “TXT” is received.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Open a command window and execute the command:

nslookup <enter>
Note: Confirm the Default Server is the DNS Server on which the command is being run.

At the nslookup prompt, type:

set type=TXT <enter>
set class=CHAOS <enter>
version.bind <enter>

If the response returns something similar to text = "Microsoft DNS 6.1.7601 (1DB14556)", this is a finding.'
  desc 'fix', 'To disable the version being returned in queries, execute the following command:

dnscmd /config /EnableVersionQuery 0 <enter>'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16834r572285_chk'
  tag severity: 'medium'
  tag gid: 'V-215640'
  tag rid: 'SV-215640r561297_rule'
  tag stig_id: 'WDNS-SI-000003'
  tag gtitle: 'SRG-APP-000333-DNS-000104'
  tag fix_id: 'F-16832r572286_fix'
  tag 'documentable'
  tag legacy: ['SV-73167', 'V-58737']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
