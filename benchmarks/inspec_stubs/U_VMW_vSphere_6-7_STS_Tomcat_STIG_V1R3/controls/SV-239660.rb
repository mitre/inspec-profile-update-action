control 'SV-239660' do
  title 'The Security Token Service must only run one web app.'
  desc 'VMware ships the Security Token Service on the VCSA with one web app, in ROOT.war. Any other .war file is potentially malicious and must be removed.'
  desc 'check', 'Connect to the PSC, whether external or embedded.

At the command prompt, execute the following command:

# ls /usr/lib/vmware-sso/vmware-sts/webapps/*.war

Expected result:

/usr/lib/vmware-sso/vmware-sts/webapps/ROOT.war

If the result of this command does not match the expected result, this is a finding.'
  desc 'fix', 'Connect to the PSC, whether external or embedded.

For each unexpected file returned in the check, run the following command:

# rm /usr/lib/vmware-sso/vmware-sts/webapps/<NAME>.war

Restart the service with the following command:

# service-control --restart vmware-stsd'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42893r816703_chk'
  tag severity: 'medium'
  tag gid: 'V-239660'
  tag rid: 'SV-239660r879584_rule'
  tag stig_id: 'VCST-67-000009'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-42852r816704_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
