control 'SV-33631' do
  title 'Disabling of email forms from the Full Trust Security Zone must be configured.'
  desc "InfoPath provides three security levels for form templates: Restricted, Domain, and Full Trust. The security levels determine whether a form template can access data on other domains, or access files and settings on your computer. Fully trusted forms have a Full Trust security level, and can access files and settings on users' computers. The form template for these forms must be digitally signed with a trusted root certificate, or installed on users' computers. 
By default, InfoPath can open e-mail forms with full trust. If an attacker designs and sends a dangerous fully trusted e-mail form, it could affect users' computers or give the attacker access to sensitive information."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable e-mail forms from the Full Trust security zone” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\security

Criteria: If the value EnableFullTrustEmailForms is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable e-mail forms from the Full Trust security zone” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17655'
  tag rid: 'SV-33631r1_rule'
  tag stig_id: 'DTOO173 - InfoPath'
  tag gtitle: 'DTOO173 - E-Mail forms from Full Trust Zone'
  tag fix_id: 'F-29774r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
