control 'SV-102595' do
  title 'The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.'
  desc 'Scripts allow server-side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server.

To ensure scripts are not added to the web server and run maliciously, script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', 'Locate cgi-bin files and directories enabled in the Apache configuration via "Script", "ScriptAlias" or "ScriptAliasMatch", or "ScriptInterpreterSource" directives.

If any script is present that is not needed for application operation, this is a finding.'
  desc 'fix', 'Remove any scripts in cgi-bin directory if they are not needed for application operation.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92507'
  tag rid: 'SV-102595r1_rule'
  tag stig_id: 'AS24-W2-000310'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-98749r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
