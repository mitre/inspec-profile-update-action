control 'SV-53887' do
  title 'Plain Text Options for outbound email must be configured.'
  desc 'If outgoing mail is formatted in certain ways, for example, if attachments are encoded in UUENCODE format, attackers might manipulate the messages for their own purposes. If UUENCODE formatting is used, an attacker could manipulate the encoded attachment to bypass content filtering software.
Outlook 2013 automatically wraps plain text messages and uses the standard MIME format to encode attachments in plain text messages. However, these settings can be altered to allow email to be read in plain text email programs that use a nonstandard line length or that cannot process MIME attachments.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Outlook Options >> Mail format >> Internet Formatting "Plain text options" is set to "Enabled" where line length is between “30” and "132" and that a check does not exist in the "Encode all attachments in UUENCODE format when sending a plain text message" check box option.

Procedure: Use the Windows Registry Editor to navigate to the following key:

Criteria: If the value for HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\common\\mailsettings\\PlainWrapLen is REG_DWORD = a value of between 30 and 132 (decimal) and the value for HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\mail\\Message Plain Format Mime is “REG_DWORD = 1”, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Outlook Options >> Mail format >> Internet Formatting "Plain text >> options" to "Enabled" where line length is between “30” and "132" and that NO Check is visible in the "Encode all attachments in UUENCODE format when sending a plain text message" check box option.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47919r3_chk'
  tag severity: 'medium'
  tag gid: 'V-17761'
  tag rid: 'SV-53887r2_rule'
  tag stig_id: 'DTOO228'
  tag gtitle: 'DTOO228 - Plain Text Options'
  tag fix_id: 'F-46793r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
