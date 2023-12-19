control 'SV-237227' do
  title 'ColdFusion must have Robust Exception Information disabled.'
  desc 'Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team.

ColdFusion is a development and deployment framework.  To handle this role properly, ColdFusion offers several debugging and logging facilities that must be disabled in a production environment.  If left enabled, these settings can expose sensitive data within error and log messages.'
  desc 'check', 'Within the Administrator Console, navigate to the "Debug Output Settings" page under the "Debugging & Output Settings" menu.

If "Enable Robust Exception Information" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Debug Output Settings" page under the "Debugging & Output Settings" menu.  Uncheck "Enable Robust Exception Information" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40446r641774_chk'
  tag severity: 'high'
  tag gid: 'V-237227'
  tag rid: 'SV-237227r641776_rule'
  tag stig_id: 'CF11-06-000218'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag fix_id: 'F-40409r641775_fix'
  tag 'documentable'
  tag legacy: ['SV-77017', 'V-62527']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
