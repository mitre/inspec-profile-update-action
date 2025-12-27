control 'SV-234109' do
  title 'Tanium Server files must be protected from file encryption actions.'
  desc 'Similar to any other host-based applications, the Tanium Server is subject to the restrictions other System-level software may place on an operating environment. Antivirus, Encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

https://docs.tanium.com/platform_install/platform_install/reference_host_system_security_exceptions.html.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the file-level encryption software used on the Tanium Server.

Review the settings for the file-level encryption software.

Validate exclusions exist which exclude the Tanium program files from being encrypted by the file-level encryption software.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement excluding policies within the file-level encryption software solution to exclude encryption of the Tanium Server program files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37294r610827_chk'
  tag severity: 'medium'
  tag gid: 'V-234109'
  tag rid: 'SV-234109r612749_rule'
  tag stig_id: 'TANS-SV-000043'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37259r610828_fix'
  tag 'documentable'
  tag legacy: ['SV-102291', 'V-92189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
