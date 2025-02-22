control 'SV-221302' do
  title 'Non-privileged accounts on the hosting system must only access OHS security-relevant information and functions through a distinct administrative account.'
  desc 'By separating web server security functions from non-privileged users, roles can be developed that can then be used to administer the web server. Forcing users to change from a non-privileged account to a privileged account when operating on the web server or on security-relevant information forces users to only operate as a web server administrator when necessary. Operating in this manner allows for better logging of changes and better forensic information and limits accidental changes to the web server.'
  desc 'check', '1. Check that sudo is properly configured for the account owning the OHS software.

2. If accounts other than the account that owns the OHS software can access the OHS software, this is a finding.'
  desc 'fix', '1. Configure sudo such that only the account that owns the OHS software can access it from the hosting system.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23017r414589_chk'
  tag severity: 'medium'
  tag gid: 'V-221302'
  tag rid: 'SV-221302r879717_rule'
  tag stig_id: 'OH12-1X-000035'
  tag gtitle: 'SRG-APP-000340-WSR-000029'
  tag fix_id: 'F-23006r414590_fix'
  tag 'documentable'
  tag legacy: ['SV-78993', 'V-64503']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
