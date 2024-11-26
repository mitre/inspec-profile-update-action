control 'SV-204812' do
  title 'The application server must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an application server.  Alternative physical protection measures include protected distribution systems.

In order to prevent unauthorized disclosure or modification of the information, application servers must protect data at rest by using cryptographic mechanisms.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Review application server documentation and configuration to determine if the application server implements cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.

If the application server does not implement cryptographic mechanisms to prevent unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the application server to implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4932r283077_chk'
  tag severity: 'medium'
  tag gid: 'V-204812'
  tag rid: 'SV-204812r879799_rule'
  tag stig_id: 'SRG-APP-000428-AS-000265'
  tag gtitle: 'SRG-APP-000428'
  tag fix_id: 'F-4932r283078_fix'
  tag 'documentable'
  tag legacy: ['SV-71833', 'V-57557']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
