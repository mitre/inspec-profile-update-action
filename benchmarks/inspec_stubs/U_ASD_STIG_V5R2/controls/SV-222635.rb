control 'SV-222635' do
  title 'The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.'
  desc 'Critical applications should not be hosted on a multi-purpose server with other applications. Applications that share resources are susceptible to the other shared application security defects. Even if the critical application is designed and deployed securely, an application that is not designed and deployed securely, can cause resource issues and possibly crash effecting the critical application.'
  desc 'check', 'Ask the application representative to review the servers where the application is deployed. 

Ask what other applications are deployed on those servers.

Identify the criticality of the applications installed on the system.

If a mission critical application is deployed onto the same server as non-mission critical applications, this is a finding.'
  desc 'fix', 'Deploy mission critical applications on servers that are not shared by other less critical applications.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24305r493813_chk'
  tag severity: 'medium'
  tag gid: 'V-222635'
  tag rid: 'SV-222635r864418_rule'
  tag stig_id: 'APSC-DV-003040'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24294r493814_fix'
  tag 'documentable'
  tag legacy: ['SV-84971', 'V-70349']
  tag cci: ['CCI-002828']
  tag nist: ['CP-2 (8)']
end
