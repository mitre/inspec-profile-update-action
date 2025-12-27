control 'SV-93305' do
  title 'Tanium endpoint files must be excluded from host-based intrusion prevention intervention.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other System-level software may place on an operating environment. Antivirus, IPS, Encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

https://docs.tanium.com/platform_install/platform_install/reference_host_system_security_exceptions.html.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the HIPS software used on the Tanium Clients.

Review the settings of the HIPS software.

Validate exclusions exist that exclude the Tanium program files from being restricted by HIPS.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the HIPS software solution to exclude the Tanium client program files from HIPS intervention.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78169r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78599'
  tag rid: 'SV-93305r1_rule'
  tag stig_id: 'TANS-CL-000014'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-85335r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
