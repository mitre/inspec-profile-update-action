control 'SV-216334' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Allowing continued access to accounts on the system exposes them to brute-force password-guessing attacks.'
  desc 'check', 'Verify RETRIES is set in the login file.

# grep ^RETRIES /etc/default/login

If the output is not RETRIES=3 or fewer, this is a finding.

Verify the account locks after invalid login attempts.

# grep ^LOCK_AFTER_RETRIES /etc/security/policy.conf

If the output is not LOCK_AFTER_RETRIES=YES, this is a finding.

For each user in the system, use the command:

# userattr lock_after_retries [username]

to determine if the user overrides the system value. If the output of this command is "no", this is a finding.'
  desc 'fix', %q(The root role is required.

# pfedit /etc/default/login

Change the line:

#RETRIES=5

to read

RETRIES=3 

pfedit /etc/security/policy.conf

Change the line containing

#LOCK_AFTER_RETRIES 

to read:

LOCK_AFTER_RETRIES=YES


If a user has lock_after_retries set to "no", update the user's attributes using the command:

# usermod -K lock_after_retries=yes [username])
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17570r371090_chk'
  tag severity: 'medium'
  tag gid: 'V-216334'
  tag rid: 'SV-216334r603267_rule'
  tag stig_id: 'SOL-11.1-040140'
  tag gtitle: 'SRG-OS-000021'
  tag fix_id: 'F-17568r371091_fix'
  tag 'documentable'
  tag legacy: ['V-48245', 'SV-61117']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
