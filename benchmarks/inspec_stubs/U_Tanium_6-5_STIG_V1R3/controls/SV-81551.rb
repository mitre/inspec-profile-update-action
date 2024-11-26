control 'SV-81551' do
  title 'Tanium Server files must be protected from file encryption actions.'
  desc 'Similar to any other host-based applications, the Tanium Server is subject to the restrictions other System-level software may place on an operating environment. Antivirus, Encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

https://kb.tanium.com/Security_Software_Exceptions'
  desc 'check', 'Consult with the Tanium System Administrator to determine the file encryption software used on the Tanium Server.

Review the settings for the file encryption software.

Validate exclusions exist which exclude the Tanium program files from being encrypted by the file encryption software.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement excluding policies within the file encryption software solution to exclude the file level encryption of the Tanium program files.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67697r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67061'
  tag rid: 'SV-81551r1_rule'
  tag stig_id: 'TANS-SV-000043'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-73161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
