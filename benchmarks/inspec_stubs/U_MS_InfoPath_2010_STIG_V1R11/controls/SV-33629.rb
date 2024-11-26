control 'SV-33629' do
  title 'Dynamic caching of InfoPath eMail forms must be disabled.'
  desc 'InfoPath caches form templates when they are attached to a mail item recognized as an InfoPath e-mail form. When users fill out forms running with a restricted security level, InfoPath uses the cached version of the mailed template, rather than any published version. To circumvent users filling out a published form, an attacker could e-mail an alternate version of the form, which would return the data to the sender as part of a phishing attack and could be used to gain access to confidential information.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable dynamic caching of the form template in InfoPath e-mail forms” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\infopath\\deployment

Criteria: If the value CacheMailXSN is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2010 -> InfoPath e-mail forms “Disable dynamic caching of the form template in InfoPath e-mail forms” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2010'
  tag check_id: 'C-34093r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17654'
  tag rid: 'SV-33629r1_rule'
  tag stig_id: 'DTOO169 - InfoPath'
  tag gtitle: 'DTOO169 - Disable dynamic caching / form template'
  tag fix_id: 'F-29772r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
