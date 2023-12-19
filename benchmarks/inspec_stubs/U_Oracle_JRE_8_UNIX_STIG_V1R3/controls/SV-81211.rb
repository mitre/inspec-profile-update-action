control 'SV-81211' do
  title 'Oracle JRE 8 must have a deployment.config file present.'
  desc 'By default no deployment.config file exists; thus, no system-wide deployment.properties file exists.  The file must be created. The deployment.config file is used for specifying the location and execution of system-level properties for the Java Runtime Environment. Without the deployment.config file, setting particular options for the Java control panel is impossible.'
  desc 'check', 'Verify a JRE deployment configuration file exists as indicated:

/etc/.java/deployment/deployment.config

If the configuration file does not exist as indicated, this is a finding.'
  desc 'fix', 'Create a JRE deployment configuration file as indicated:

/etc/.java/deployment/deployment.config'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67371r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66721'
  tag rid: 'SV-81211r1_rule'
  tag stig_id: 'JRE8-UX-000010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-72821r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
