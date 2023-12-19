control 'SV-206394' do
  title 'Anonymous user access to the web server application directories must be prohibited.'
  desc 'In order to properly monitor the changes to the web server and the hosted applications, logging must be enabled. Along with logging being enabled, each record must properly contain the changes made and the names of those who made the changes.

Allowing anonymous users the capability to change the web server or the hosted application will not generate proper log information that can then be used for forensic reporting in the case of a security issue. Allowing anonymous users to make changes will also grant change capabilities to anybody without forcing a user to authenticate before the changes can be made.'
  desc 'check', 'Review the web server documentation and configuration to determine if anonymous users can make changes to the web server or any applications hosted by the web server.

If anonymous users can make changes, this is a finding.'
  desc 'fix', 'Configure the web server to not allow anonymous users to change the web server or any hosted applications.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6655r377774_chk'
  tag severity: 'medium'
  tag gid: 'V-206394'
  tag rid: 'SV-206394r397711_rule'
  tag stig_id: 'SRG-APP-000211-WSR-000031'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-6655r377775_fix'
  tag 'documentable'
  tag legacy: ['SV-70247', 'V-55993']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
