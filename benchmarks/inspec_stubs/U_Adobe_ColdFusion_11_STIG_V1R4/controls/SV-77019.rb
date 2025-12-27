control 'SV-77019' do
  title 'ColdFusion must have AJAX Debug Log Window disabled.'
  desc 'Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team.

Allowing the AJAX Debug Log Window to be enabled allows a user to send AJAX debug messages back to a client.  The log data sent is meant to be used in a development environment and used to fix errors in AJAX code.  Once the application is developed and is moved to production, debugging is not needed and this feature must be disabled.'
  desc 'check', 'Within the Administrator Console, navigate to the "Debug Output Settings" page under the "Debugging & Output Settings" menu.

If "Enable AJAX Debug Log Window" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Debug Output Settings" page under the "Debugging & Output Settings" menu.  Uncheck "Enable AJAX Debug Log Window" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63333r1_chk'
  tag severity: 'high'
  tag gid: 'V-62529'
  tag rid: 'SV-77019r1_rule'
  tag stig_id: 'CF11-06-000219'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag fix_id: 'F-68449r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
