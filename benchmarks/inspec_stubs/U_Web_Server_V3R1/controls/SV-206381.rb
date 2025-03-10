control 'SV-206381' do
  title 'The web server must allow the mappings to unused and vulnerable scripts to be removed.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine what script mappings are available.

Review the scripts used by the web server and the hosted applications.

If there are script mappings in use that are not used by the web server or hosted applications for operation, this is a finding.'
  desc 'fix', 'Remove script mappings that are not needed for web server and hosted application operation.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6642r377735_chk'
  tag severity: 'medium'
  tag gid: 'V-206381'
  tag rid: 'SV-206381r395853_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000082'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6642r377736_fix'
  tag 'documentable'
  tag legacy: ['SV-54277', 'V-41700']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
