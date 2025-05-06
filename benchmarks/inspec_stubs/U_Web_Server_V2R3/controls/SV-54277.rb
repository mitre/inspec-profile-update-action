control 'SV-54277' do
  title 'The web server must allow the mappings to unused and vulnerable scripts to be removed.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine what script mappings are available.

Review the scripts used by the web server and the hosted applications.

If there are script mappings in use that are not used by the web server or hosted applications for operation, this is a finding.'
  desc 'fix', 'Remove script mappings that are not needed for web server and hosted application operation.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48097r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41700'
  tag rid: 'SV-54277r3_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000082'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-47159r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
