control 'SV-253813' do
  title 'Tanium endpoint files must be excluded from host-based intrusion prevention system (HIPS) intervention.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other system-level software may place on an operating environment. Antivirus, intrusion prevention system (IPS), encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

For more information, refer to https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/security_exceptions.html?Highlight=exclusion.'
  desc 'check', 'Consult with the Tanium system administrator to determine the HIPS software used on the Tanium Clients.

Review the settings of the HIPS software.

Validate exclusions exist that exclude the Tanium program files from being restricted by HIPS.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the HIPS software solution to exclude the Tanium client program files from HIPS intervention.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57265r842465_chk'
  tag severity: 'medium'
  tag gid: 'V-253813'
  tag rid: 'SV-253813r842467_rule'
  tag stig_id: 'TANS-CL-000014'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-57216r842466_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
