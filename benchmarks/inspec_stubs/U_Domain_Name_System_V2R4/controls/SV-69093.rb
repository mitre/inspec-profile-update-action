control 'SV-69093' do
  title 'The DNS Name Server software must be configured to refuse queries for its version information.'
  desc 'Each newer version of the name server software, especially the BIND software, generally is devoid of vulnerabilities found in earlier versions because it has design changes incorporated to take care of those vulnerabilities. Of course, these vulnerabilities have been exploited (i.e., some form of attack was launched), and sufficient information has been generated with respect to the nature of those exploits. Thus, it makes good business sense to run the latest version of name server software because theoretically it is the safest version. 

In some installations, it may not be possible to switch over to the latest version of name server software immediately. If the version of the name server software is revealed in queries, this information may be used by attackers who are looking for a specific version of the software which has a discovered weakness. To prevent information about which version of name server software is running on a system, name servers should be configured to refuse queries for its version information.'
  desc 'check', 'Review the DNS configuration files. Verify the DNS name server is explicitly configured to refuse queries asking for its version information.

If the name server is not configured to explicitly refuse queries asking for its version information, this is a finding.'
  desc 'fix', 'Configure the name server to refuse queries for its version information.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55469r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54847'
  tag rid: 'SV-69093r1_rule'
  tag stig_id: 'SRG-APP-000333-DNS-000104'
  tag gtitle: 'SRG-APP-000333-DNS-000104'
  tag fix_id: 'F-59705r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002201']
  tag nist: ['AC-4 (12)']
end
