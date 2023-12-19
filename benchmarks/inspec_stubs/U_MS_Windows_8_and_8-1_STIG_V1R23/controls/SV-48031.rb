control 'SV-48031' do
  title 'The minimum password age must meet requirements.'
  desc 'Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database.  This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Password Policy.

If the value for the "Minimum password age" is less than one day, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Minimum Password Age" to at least "1" day.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1105'
  tag rid: 'SV-48031r1_rule'
  tag stig_id: 'WN08-AC-000006'
  tag gtitle: 'Minimum Password Age'
  tag fix_id: 'F-41169r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
