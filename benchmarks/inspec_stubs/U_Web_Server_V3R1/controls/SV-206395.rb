control 'SV-206395' do
  title 'The web server must separate the hosted applications from hosted web server management functionality.'
  desc 'The separation of user functionality from web server management can be accomplished by moving management functions to a separate IP address or port.  To further separate the management functions, separate authentication methods and certificates should be used.  

By moving the management functionality, the possibility of accidental discovery of the management functions by non-privileged users during hosted application use is minimized.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether hosted application functionality is separated from web server management functions.

If the functions are not separated, this is a finding.'
  desc 'fix', 'Configure the web server to separate the hosted applications from web server management functionality.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6656r377777_chk'
  tag severity: 'medium'
  tag gid: 'V-206395'
  tag rid: 'SV-206395r397711_rule'
  tag stig_id: 'SRG-APP-000211-WSR-000129'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-6656r377778_fix'
  tag 'documentable'
  tag legacy: ['SV-54371', 'V-41794']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
