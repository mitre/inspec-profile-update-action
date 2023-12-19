control 'SV-223507' do
  title 'ACF2 PSWD GSO record value must be set to require 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If "PSWDMIN" is set "1", this is not a finding.'
  desc 'fix', 'Configure Password option "PSWDMIN" to minimum of "1" day.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25180r695438_chk'
  tag severity: 'medium'
  tag gid: 'V-223507'
  tag rid: 'SV-223507r695439_rule'
  tag stig_id: 'ACF2-ES-000900'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-25168r500655_fix'
  tag 'documentable'
  tag legacy: ['V-97717', 'SV-106821']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
