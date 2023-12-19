control 'SV-222412' do
  title 'Unnecessary application accounts must be disabled, or deleted.'
  desc 'Test or demonstration accounts are sometimes created during the application installation process. This creates a security risk as these accounts often remain after the initial installation process and can be used to gain unauthorized access to the application. Applications must be designed and configured to disable or delete any unnecessary accounts that may be created. 

Care must be taken to ensure valid accounts used for valid application operations are not disabled or deleted when this requirement is applied.'
  desc 'check', 'Review the system documentation and identify any valid application accounts that are required in order for the application to operate. Accounts the application itself uses in order to function are not in scope for this requirement.

Have the application administrator generate a list of all application users. This should include relevant user metadata such as phone numbers or department identifiers.

Have the application administrator identify and validate all user accounts.

If any accounts cannot be validated and are deemed to be unnecessary, this is a finding.'
  desc 'fix', 'Design the application so unessential user accounts are not created during installation. Disable or delete all unnecessary application user accounts.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24082r493144_chk'
  tag severity: 'medium'
  tag gid: 'V-222412'
  tag rid: 'SV-222412r879524_rule'
  tag stig_id: 'APSC-DV-000330'
  tag gtitle: 'SRG-APP-000025'
  tag fix_id: 'F-24071r493145_fix'
  tag 'documentable'
  tag legacy: ['V-69303', 'SV-83925']
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
