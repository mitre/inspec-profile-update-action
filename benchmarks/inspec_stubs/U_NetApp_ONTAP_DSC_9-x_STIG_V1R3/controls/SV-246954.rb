control 'SV-246954' do
  title 'ONTAP must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Use "security login role config show -role admin -fields passwd-alphanum" to see at least one letter and one number are required in a password for the role admin.

If ONTAP is not configured to enforce password complexity by requiring that at least one numeric character be used, this is a finding.'
  desc 'fix', 'Configure ONTAP to enforce password complexity by requiring that at least one numeric character be used with "security login role config modify -role admin -passwd-alphanum enabled".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50386r835263_chk'
  tag severity: 'medium'
  tag gid: 'V-246954'
  tag rid: 'SV-246954r835264_rule'
  tag stig_id: 'NAOT-IA-000008'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-50340r769193_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
