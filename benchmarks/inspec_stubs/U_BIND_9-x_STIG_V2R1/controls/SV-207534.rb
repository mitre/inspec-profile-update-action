control 'SV-207534' do
  title 'The platform on which the name server software is hosted must only run processes and services needed to support the BIND 9.x implementation.'
  desc 'Hosts that run the name server software should not provide any other services. Unnecessary services running on the DNS server can introduce additional attack vectors leading to the compromise of an organization’s DNS architecture.'
  desc 'check', 'Verify that the BIND 9.x server is dedicated for DNS traffic:

With the assistance of the DNS administrator, identify all of the processes running on the BIND 9.x server:

# ps -ef | less

If any of the identified processes are not in support of normal OS functionality or in support of the BIND 9.x process, this is a finding.'
  desc 'fix', 'Disable or uninstall all non-DNS related applications from the BIND 9.x server.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7789r283656_chk'
  tag severity: 'medium'
  tag gid: 'V-207534'
  tag rid: 'SV-207534r612253_rule'
  tag stig_id: 'BIND-9X-001002'
  tag gtitle: 'SRG-APP-000516-DNS-000109'
  tag fix_id: 'F-7789r283657_fix'
  tag 'documentable'
  tag legacy: ['SV-86991', 'V-72367']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
