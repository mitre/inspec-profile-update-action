control 'SV-54046' do
  title 'Permit download of content from safe zones must be configured.'
  desc 'By default, Outlook automatically downloads content from sites that are considered "safe," as defined in the Security tab of the Internet Options dialog box in Internet Explorer. This configuration could allow users to inadvertently download Web beacons that reveal their identity to spammers and other malicious people.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Automatic Picture Download Settings "Do not permit download of content from safe zones" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\mail

Criteria: If the value UnblockSafeZone is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Automatic Picture Download Settings "Do not permit download of content from safe zones" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47984r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17470'
  tag rid: 'SV-54046r1_rule'
  tag stig_id: 'DTOO272'
  tag gtitle: 'DTOO272 - Content download from safe zones'
  tag fix_id: 'F-46925r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
