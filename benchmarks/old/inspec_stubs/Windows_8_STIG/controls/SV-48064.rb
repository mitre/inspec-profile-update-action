control 'SV-48064' do
  title 'Reversible password encryption must be disabled.'
  desc 'Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords. For this reason, this policy must never be enabled.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Password Policy.

If the value for "Store password using reversible encryption" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Store password using reversible encryption" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44803r1_chk'
  tag severity: 'high'
  tag gid: 'V-2372'
  tag rid: 'SV-48064r1_rule'
  tag stig_id: 'WN08-AC-000009'
  tag gtitle: 'Reversible Password Encryption'
  tag fix_id: 'F-41202r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
