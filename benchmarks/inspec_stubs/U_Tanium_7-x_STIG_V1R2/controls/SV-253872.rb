control 'SV-253872' do
  title 'Tanium Server files must be excluded from host-based intrusion prevention intervention.'
  desc 'Similar to any other host-based applications, the Tanium Server is subject to the restrictions other system-level software may place on an operating environment. Antivirus, intrusion prevention system (IPS), encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

For more information, refer to https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/security_exceptions.html?Highlight=exclusion.'
  desc 'check', 'Consult with the Tanium system administrator to determine the HIPS software used on the Tanium Server.

Review the settings of the HIPS software.

Validate exclusions exist that exclude the Tanium program files from being restricted by HIPS.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the HIPS software solution to exclude the Tanium Server program files from HIPS intervention.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57324r842642_chk'
  tag severity: 'medium'
  tag gid: 'V-253872'
  tag rid: 'SV-253872r842644_rule'
  tag stig_id: 'TANS-SV-000065'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-57275r842643_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
