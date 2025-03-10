control 'SV-32314' do
  title 'Reversible password encryption will be disabled.'
  desc 'Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords. For this reason, this policy should never be enabled.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view. Navigate to Account Policies -> Password Policy. 

If the value for “Store password using reversible encryption” is not disabled, then this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> “Store password using reversible encryption” to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32887r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2372'
  tag rid: 'SV-32314r1_rule'
  tag gtitle: 'Reversible Password Encryption'
  tag fix_id: 'F-28816r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
