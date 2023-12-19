control 'SV-240790' do
  title 'tc Server ALL must have all mappings to unused and vulnerable scripts to be removed.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed. Because tc Server is installed as part of the entire vRA application, and not installed separately, VMware has ensured that scripts not needed for application operation or deemed vulnerable have been removed from tc Server.'
  desc 'check', 'Interview the ISSO.

Review the web server documentation and deployed configuration to determine if all mappings to unused and vulnerable scripts to be removed.

If all mappings to unused and vulnerable scripts have not been removed, this is a finding.'
  desc 'fix', 'Remove script mappings that are not needed for web server and hosted application operation.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44023r674112_chk'
  tag severity: 'medium'
  tag gid: 'V-240790'
  tag rid: 'SV-240790r674114_rule'
  tag stig_id: 'VRAU-TC-000365'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-43982r674113_fix'
  tag 'documentable'
  tag legacy: ['SV-100663', 'V-90013']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
