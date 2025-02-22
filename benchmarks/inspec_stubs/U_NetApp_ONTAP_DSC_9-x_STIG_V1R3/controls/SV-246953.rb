control 'SV-246953' do
  title 'ONTAP must enforce password complexity by requiring that at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Use "security login role config show -role admin -fields passwd-min-lowercase-chars" to see the minimum number of lowercase characters required in a password for the role admin.

If ONTAP is not configured to enforce password complexity by requiring that at least one lowercase character be used, this is a finding.'
  desc 'fix', 'Configure ONTAP to enforce password complexity by requiring that at least one lowercase character be used for the role admin with "security login role config modify  -role admin -passwd-min-lowercase-chars 1".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50385r835260_chk'
  tag severity: 'medium'
  tag gid: 'V-246953'
  tag rid: 'SV-246953r835262_rule'
  tag stig_id: 'NAOT-IA-000007'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-50339r835261_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
