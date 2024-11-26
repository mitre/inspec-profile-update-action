control 'SV-223160' do
  title 'Firefox formfill assistance option is disabled.'
  desc 'In order to protect privacy and sensitive data, Firefox provides the ability to configure Firefox such that data entered into forms is not saved.  This mitigates the risk of a website gleaning private information from prefilled information.'
  desc 'check', 'Type "about:config" in the address bar, verify that the preference name “browser.formfill.enable" is set to “false” and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding.  If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “browser.formfill.enable" is set and locked to the value of “false”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24833r531297_chk'
  tag severity: 'medium'
  tag gid: 'V-223160'
  tag rid: 'SV-223160r612236_rule'
  tag stig_id: 'DTBF140'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24821r531298_fix'
  tag 'documentable'
  tag legacy: ['SV-16713', 'V-15774']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
