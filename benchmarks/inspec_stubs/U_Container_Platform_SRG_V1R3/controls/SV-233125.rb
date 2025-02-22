control 'SV-233125' do
  title 'The container platform runtime must isolate security functions from non-security functions.'
  desc 'The container platform runtime must be configured to isolate those services used for security functions from those used for non-security functions. This separation can be performed using environment variables, labels, network segregation, and kernel groups.'
  desc 'check', 'Verify container platform runtime configuration settings to determine whether container services used for security functions are located in an isolated security function such as a separate environment variables, labels, network segregation, and kernel groups.

If security-related functions are not separate, this is a finding.'
  desc 'fix', 'Configure the container platform runtime to isolate security functions from non-security functions.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36061r601750_chk'
  tag severity: 'medium'
  tag gid: 'V-233125'
  tag rid: 'SV-233125r601751_rule'
  tag stig_id: 'SRG-APP-000233-CTR-000585'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-36029r600863_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
