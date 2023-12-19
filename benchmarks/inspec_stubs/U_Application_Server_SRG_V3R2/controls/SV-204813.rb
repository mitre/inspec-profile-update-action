control 'SV-204813' do
  title 'The application must implement cryptographic mechanisms to prevent unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an application server.  Alternative physical protection measures include protected distribution systems.

In order to prevent unauthorized disclosure or modification of the information, application servers must protect data at rest by using cryptographic mechanisms.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server implements cryptographic mechanisms to prevent unauthorized disclosure of organization-defined information at rest on organization-defined information system components.

If the application server does not implement cryptographic mechanisms to prevent unauthorized disclosure, this is a finding.'
  desc 'fix', 'Configure the application server to implement cryptographic mechanisms to prevent unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4933r283080_chk'
  tag severity: 'medium'
  tag gid: 'V-204813'
  tag rid: 'SV-204813r508029_rule'
  tag stig_id: 'SRG-APP-000429-AS-000157'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-4933r283081_fix'
  tag 'documentable'
  tag legacy: ['V-57559', 'SV-71835']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
