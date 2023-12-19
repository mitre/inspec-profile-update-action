control 'SV-246952' do
  title 'ONTAP must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Use "security login role config show -role admin -fields passwd-min-uppercase-chars" to see the minimum number of uppercase characters required in a password for the role admin.

If ONTAP cannot be configured to enforce password complexity by requiring that at least one upper-case character be used, this is a finding.'
  desc 'fix', 'Configure ONTAP to enforce password complexity by requiring that at least one upper-case character be used for the role admin with "security login role config modify  -role admin -passwd-min-uppercase-chars 1".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50384r769186_chk'
  tag severity: 'medium'
  tag gid: 'V-246952'
  tag rid: 'SV-246952r781014_rule'
  tag stig_id: 'NAOT-IA-000006'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-50338r769187_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
