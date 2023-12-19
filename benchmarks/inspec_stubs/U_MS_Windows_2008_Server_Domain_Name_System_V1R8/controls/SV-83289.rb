control 'SV-83289' do
  title 'The DNS name server software must be at the latest version.'
  desc 'Each newer version of the name server software, especially the BIND software, generally is devoid of vulnerabilities found in earlier versions because it has design changes incorporated to take care of those vulnerabilities. These vulnerabilities have been exploited (i.e., some form of attack was launched), and sufficient information has been generated with respect to the nature of those exploits. It makes good business sense to run the latest version of name server software because theoretically it is the safest version. Even if the software is the latest version, it is not safe to run it in default mode. The security administrator should always configure the software to run in the recommended secure mode of operation after becoming familiar with the new security settings for the latest version.'
  desc 'check', 'Consult with the network IAVM scanner to confirm all Microsoft Operating System IAVMs have been applied to the Windows DNS server.

If all Microsoft Operating System IAVMs have not been applied to the DNS server, this is a finding.'
  desc 'fix', 'Apply all related Microsoft Operating System IAVM patches to the DNS server.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59489r3_chk'
  tag severity: 'medium'
  tag gid: 'V-58617'
  tag rid: 'SV-83289r1_rule'
  tag stig_id: 'WDNS-CM-000023'
  tag gtitle: 'SRG-APP-000516-DNS-000103'
  tag fix_id: 'F-64001r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
