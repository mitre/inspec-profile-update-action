control 'SV-239410' do
  title 'Performance Charts must only run one web app.'
  desc 'VMware ships Performance Charts on the VCSA with one web app. Any other path is potentially malicious and must be removed.'
  desc 'check', 'At the command prompt, execute the following command:

# ls -A /usr/lib/vmware-perfcharts/tc-instance/webapps

Expected result:

statsreport

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'For each unexpected directory returned in the check, run the following command:

# rm /usr/lib/vmware-sso/vmware-sts/webapps/<NAME>

Restart the service with the following command:

# service-control --restart vmware-perfcharts'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Perfcharts Tomcat'
  tag check_id: 'C-42643r674951_chk'
  tag severity: 'medium'
  tag gid: 'V-239410'
  tag rid: 'SV-239410r674953_rule'
  tag stig_id: 'VCPF-67-000009'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-42602r674952_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
