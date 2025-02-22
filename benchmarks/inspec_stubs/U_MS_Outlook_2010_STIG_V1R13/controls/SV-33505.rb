control 'SV-33505' do
  title 'Plain Text Options for outbound email must be configured.'
  desc 'If outgoing mail is formatted in certain ways, for example if attachments are encoded in UUENCODE format, attackers might manipulate the messages for their own purposes. If UUENCODE formatting is used, an attacker could manipulate the encoded attachment to bypass content filtering software.
Outlook 2010 automatically wraps plain text messages and uses the standard MIME format to encode attachments in plain text messages. However, these settings can be altered to allow e-mail to be read in plain text e-mail programs that use a non-standard line length or that cannot process MIME attachments.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail format -> Internet Formatting "Plain text options" must be set to "Enabled" where line length is "132" and that NO Check is visible in the "Encode all attachments in UUENCODE format when sending a plain text message" checkbox option. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\mailsettings

Criteria: If the value PlainWrapLen is REG_DWORD = 132 (decimal), this is not a finding.

AND

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value Message Plain Format Mime is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail format -> Internet Formatting "Plain text -> options" to "Enabled" where line length is "132" and that NO Check is visible in the "Encode all attachments in UUENCODE format when sending a plain text message" checkbox option.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33991r3_chk'
  tag severity: 'medium'
  tag gid: 'V-17761'
  tag rid: 'SV-33505r2_rule'
  tag stig_id: 'DTOO228 - Outlook'
  tag gtitle: 'DTOO228 - Plain Text Options'
  tag fix_id: 'F-29680r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
