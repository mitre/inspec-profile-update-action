control 'SV-253812' do
  title 'Tanium Client directory and subsequent files must be excluded from On-Access scan.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other system-level software may place on an operating environment. Antivirus, intrusion prevention system (IPS), encryption, or other security and management stack software may disallow the Client from working as expected.

For more information, refer to https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/security_exceptions.html?Highlight=exclusion.'
  desc 'check', 'Review the settings of the antivirus software.

Validate exclusions exist that exclude the Tanium Client directory and subsequent file interactions from On-Access scans. 

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the antivirus software solution to exclude the On-Access scanning of Tanium Client directory and subsequent file interactions.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57264r842462_chk'
  tag severity: 'medium'
  tag gid: 'V-253812'
  tag rid: 'SV-253812r842464_rule'
  tag stig_id: 'TANS-CL-000008'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-57215r842463_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
