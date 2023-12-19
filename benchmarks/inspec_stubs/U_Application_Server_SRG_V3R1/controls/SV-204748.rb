control 'SV-204748' do
  title 'The application server must authenticate users individually prior to using a group authenticator.'
  desc 'To assure individual accountability and prevent unauthorized access, application server users (and any processes acting on behalf of application server users) must be individually identified and authenticated. 

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. 

Application servers must ensure that individual users are authenticated prior to authenticating via role or group authentication. This is to ensure that there is non-repudiation for actions taken.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server individually authenticates users prior to authenticating via a role or group.

Review application server logs to verify user accesses requiring authentication can be traced back to an individual account.

If the application server does not authenticate users on an individual basis, this is a finding.'
  desc 'fix', 'Configure the application server to authenticate users individually prior to allowing any group-based authentication.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4868r282891_chk'
  tag severity: 'medium'
  tag gid: 'V-204748'
  tag rid: 'SV-204748r508029_rule'
  tag stig_id: 'SRG-APP-000153-AS-000104'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-4868r282892_fix'
  tag 'documentable'
  tag legacy: ['V-35302', 'SV-46589']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
