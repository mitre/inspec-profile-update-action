control 'SV-237229' do
  title 'ColdFusion must have Request Debugging Output disabled.'
  desc 'Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team.

The option to enable request debugging output is another tool that a developer can use during the development phase of the hosted application.  This feature appends debugging information to the end of each CFML request.  Once a hosted application is moved from the development phase to production, the need for debug information is no longer valid.'
  desc 'check', 'Within the Administrator Console, navigate to the "Debug Output Settings" page under the "Debugging & Output Settings" menu.

If "Enable Request Debugging Output" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Debug Output Settings" page under the "Debugging & Output Settings" menu.  Uncheck "Enable Request Debugging Output" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40448r641780_chk'
  tag severity: 'high'
  tag gid: 'V-237229'
  tag rid: 'SV-237229r641782_rule'
  tag stig_id: 'CF11-06-000220'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag fix_id: 'F-40411r641781_fix'
  tag 'documentable'
  tag legacy: ['SV-77021', 'V-62531']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
