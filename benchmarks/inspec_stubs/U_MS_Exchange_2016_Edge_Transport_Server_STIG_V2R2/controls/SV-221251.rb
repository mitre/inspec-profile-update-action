control 'SV-221251' do
  title 'Exchange must have antispam filtering configured.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2016 provides both antispam and antimalware protection out of the box. The Exchange 2016 antispam and antimalware product capabilities are limited but still provide some protection.'
  desc 'check', 'Site should utilize an approved DoD scanner as Exchange Malware software has a limited scanning capability.

If an approved DoD scanner is not being used, this is a finding.'
  desc 'fix', 'Following vendor best practice guidance, install and configure a DoD approved scanner.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22966r411879_chk'
  tag severity: 'medium'
  tag gid: 'V-221251'
  tag rid: 'SV-221251r612603_rule'
  tag stig_id: 'EX16-ED-000550'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22955r411880_fix'
  tag 'documentable'
  tag legacy: ['SV-95293', 'V-80583']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
