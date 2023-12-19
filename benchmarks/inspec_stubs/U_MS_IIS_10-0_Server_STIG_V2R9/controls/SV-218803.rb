control 'SV-218803' do
  title 'The IIS 10.0 web server must separate the hosted applications from hosted web server management functionality.'
  desc 'The separation of user functionality from web server management can be accomplished by moving management functions to a separate IP address or port. To further separate the management functions, separate authentication methods and certificates should be used.

By moving the management functionality, the possibility of accidental discovery of the management functions by non-privileged users during hosted application use is minimized.'
  desc 'check', "Review the IIS 10.0 web server configuration with the System Administrator.

Determine if the IIS 10.0 web server hosts any applications.

If the IIS 10.0 web server does not host any applications, this is Not Applicable.

If the IIS 10.0 web server is hosting Exchange, this is Not Applicable.

If the IIS 10.0 web server hosts applications, review the application's management functionality and authentication methods with the System Administrator to determine if the management of the application is accomplished with the same functions and authentication methods as the web server management.

If the IIS 10.0 web server management and the application's management functionality is not separated, this is a finding."
  desc 'fix', "Develop a method to manage the hosted applications, either by moving its management functions off of the IIS 10.0 web server or by accessing the application's management via a uniquely assigned IP address."
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20275r570474_chk'
  tag severity: 'medium'
  tag gid: 'V-218803'
  tag rid: 'SV-218803r879631_rule'
  tag stig_id: 'IIST-SV-000132'
  tag gtitle: 'SRG-APP-000211-WSR-000129'
  tag fix_id: 'F-20273r310885_fix'
  tag 'documentable'
  tag legacy: ['SV-109245', 'V-100141']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
