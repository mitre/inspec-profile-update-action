control 'SV-54064' do
  title 'Outlook minimum encryption key length settings must be set.'
  desc 'This setting allows the minimum key length for an encrypted email message to be configured.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Minimum encryption settings" is set to "Enabled: 168 bits".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value MinEncKey is REG_DWORD = 168, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Minimum encryption settings" to "Enabled: 168 bits".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-48004r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26636'
  tag rid: 'SV-54064r1_rule'
  tag stig_id: 'DTOO316'
  tag gtitle: 'DTOO316 - Minimum encryption settings'
  tag fix_id: 'F-46944r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
