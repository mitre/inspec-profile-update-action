control 'SV-205503' do
  title 'The Mainframe Product must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy-based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configuration does not enforce 24 hours/1 day as the minimum password lifetime, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management to enforce 24 hours/1 day as the minimum password lifetime.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5769r299742_chk'
  tag severity: 'medium'
  tag gid: 'V-205503'
  tag rid: 'SV-205503r397588_rule'
  tag stig_id: 'SRG-APP-000173-MFP-000235'
  tag gtitle: 'SRG-APP-000173'
  tag fix_id: 'F-5769r299743_fix'
  tag 'documentable'
  tag legacy: ['SV-82879', 'V-68389']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
