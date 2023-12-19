control 'SV-69195' do
  title 'The DNS name server software must be at the latest version.'
  desc 'Each newer version of the name server software, especially the BIND software, generally is devoid of vulnerabilities found in earlier versions because it has design changes incorporated to take care of those vulnerabilities. These vulnerabilities have been exploited (i.e., some form of attack was launched), and sufficient information has been generated with respect to the nature of those exploits. It makes good business sense to run the latest version of name server software because theoretically it is the safest version. Even if the software is the latest version, it is not safe to run it in default mode. The security administrator should always configure the software to run in the recommended secure mode of operation after becoming familiar with the new security settings for the latest version.'
  desc 'check', 'Review the DNS implementation to determine the name server software version.

If the installed name server software version is not the latest production version, this is a finding.'
  desc 'fix', 'Update the installed name server software with the latest production version.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55575r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54949'
  tag rid: 'SV-69195r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000103'
  tag gtitle: 'SRG-APP-000516-DNS-000103'
  tag fix_id: 'F-59811r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
