control 'SV-33512' do
  title 'Dragging Unicode eMail messages to file system must be disallowed.'
  desc 'When users drag e-mail messages from Outlook to a Windows Explorer window or to their Desktop, Outlook creates a .msg file using the native character encoding format for the configured locale (the so-called "ANSI" format). If this setting is Enabled, Outlook uses the Unicode character encoding standard to create the message file, which preserves special characters in the message. 
However, Unicode text is vulnerable to homograph attacks, in which characters are replaced by different but similar-looking characters. For example, the Cyrillic letter ? (U+0430) appears identical to the Latin letter a (U+0061) in many typefaces, but is actually a different character. Homographs can be used in "phishing" attacks to convince victims to visit fraudulent Web sites and enter sensitive information.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Other -> Advanced “Use Unicode format when dragging e-mail message to file system”  must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\general

Criteria: If the value MSGFormat is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Other -> Advanced “Use Unicode format when dragging e-mail message to file system” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33999r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17812'
  tag rid: 'SV-33512r1_rule'
  tag stig_id: 'DTOO231 - Outlook'
  tag gtitle: 'DTOO231 - Unicode use when dragging Email'
  tag fix_id: 'F-29687r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
