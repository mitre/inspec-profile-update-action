control 'SV-93301' do
  title 'Tanium endpoint files must be protected from file encryption actions.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other System-level software may place on an operating environment. That is to say that Antivirus, Encryption, or other security and management stack software may disallow the Client from working as expected.

https://docs.tanium.com/platform_install/platform_install/reference_host_system_security_exceptions.html'
  desc 'check', 'Consult with the Tanium System Administrator to determine the file-based encryption software used on the Tanium clients.

Review the settings for the file-based encryption software.

Validate exclusions exist that exclude the Tanium program files from being encrypted by the file-based encryption software.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement excluding policies within the file-based encryption software solution to exclude the file level encryption of the Tanium client program files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78165r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78595'
  tag rid: 'SV-93301r1_rule'
  tag stig_id: 'TANS-CL-000012'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-85331r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
