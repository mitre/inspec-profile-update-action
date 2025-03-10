control 'SV-225274' do
  title 'Reversible password encryption must be disabled.'
  desc 'Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords.  For this reason, this policy must never be enabled.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for "Store password using reversible encryption" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Store password using reversible encryption" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26973r471164_chk'
  tag severity: 'high'
  tag gid: 'V-225274'
  tag rid: 'SV-225274r877397_rule'
  tag stig_id: 'WN12-AC-000009'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-26961r471165_fix'
  tag 'documentable'
  tag legacy: ['V-2372', 'SV-52880']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
