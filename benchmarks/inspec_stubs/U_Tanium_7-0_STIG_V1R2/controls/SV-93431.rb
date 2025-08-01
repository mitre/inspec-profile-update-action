control 'SV-93431' do
  title 'Tanium Server files must be protected from file encryption actions.'
  desc 'Similar to any other host-based applications, the Tanium Server is subject to the restrictions other System-level software may place on an operating environment. Antivirus, Encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

https://docs.tanium.com/platform_install/platform_install/reference_host_system_security_exceptions.html.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the file-level encryption software used on the Tanium Server.

Review the settings for the file-level encryption software.

Validate exclusions exist that exclude the Tanium program files from being encrypted by the file-level encryption software.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement excluding policies within the file-level encryption software solution to exclude encryption of the Tanium Server program files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78295r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78725'
  tag rid: 'SV-93431r1_rule'
  tag stig_id: 'TANS-SV-000043'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-85461r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
