control 'SV-214374' do
  title 'The Apache web server must separate the hosted applications from hosted Apache web server management functionality.'
  desc 'The separation of user functionality from web server management can be accomplished by moving management functions to a separate IP address or port. To further separate the management functions, separate authentication methods and certificates should be used.

By moving the management functionality, the possibility of accidental discovery of the management functions by non-privileged users during hosted application use is minimized.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether hosted application functionality is separated from web server management functions.

If the functions are not separated, this is a finding.'
  desc 'fix', 'Configure Apache to separate the hosted applications from web server management functionality.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15585r277863_chk'
  tag severity: 'medium'
  tag gid: 'V-214374'
  tag rid: 'SV-214374r397711_rule'
  tag stig_id: 'AS24-W2-000450'
  tag gtitle: 'SRG-APP-000211-WSR-000129'
  tag fix_id: 'F-15583r277864_fix'
  tag 'documentable'
  tag legacy: ['SV-102619', 'V-92531']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
