control 'SV-81483' do
  title 'Tanium endpoint files must be protected from file encryption actions.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other System-level software may place on an operating environment. That is to say that Antivirus, Encryption, or other security and management stack software may disallow the Client from working as expected.

https://kb.tanium.com/Security_Software_Exceptions'
  desc 'check', 'Consult with the Tanium System Administrator to determine the file encryption software used on the Tanium clients.

Review the settings for the file encryption software.

Validate exclusions exist which exclude the Tanium program files from being encrypted by the file encryption software.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement excluding policies within the file encryption software solution to exclude the file level encryption of the Tanium program files.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66993'
  tag rid: 'SV-81483r1_rule'
  tag stig_id: 'TANS-CL-000012'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-73093r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
