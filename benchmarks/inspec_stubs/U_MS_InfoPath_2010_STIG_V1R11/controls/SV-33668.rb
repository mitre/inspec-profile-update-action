control 'SV-33668' do
  title 'Unsafe file types must be prevented from being attached to InfoPath forms.'
  desc 'Users can attach any type of file to forms except potentially unsafe files that might contain viruses, such as .bat or .exe files. For the full list of file types that InfoPath disallows by default, see "Security Details" in Insert a file attachment control on the Microsoft Office Online Web site.
If unsafe file types are added to InfoPath forms, they might be used as a means of attacking the computer on which the form is opened. These unsafe file types may include active content, or may introduce other vulnerabilities that an attacker can exploit.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Prevent users from allowing unsafe file types to be attached to forms” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\security

Criteria: If the value DisallowAttachmentCustomization is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> Security -> “Prevent users from allowing unsafe file types to be attached to forms” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34128r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17764'
  tag rid: 'SV-33668r1_rule'
  tag stig_id: 'DTOO160 - InfoPath'
  tag gtitle: 'DTOO160 - Unsafe File Attachments in InfoPath'
  tag fix_id: 'F-29810r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
