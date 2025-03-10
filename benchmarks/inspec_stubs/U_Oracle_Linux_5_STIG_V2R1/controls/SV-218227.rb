control 'SV-218227' do
  title 'The system must require passwords contain a minimum of 15 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'check', 'Check the system password length setting.

Procedure:
Check the password minlen option
# grep pam_cracklib.so /etc/pam.d/system-auth

Confirm the minlen option is set to at least 15 as in the example below:

password required pam_cracklib.so minlen=15

There may be other options on the line. If no such line is found, or the minlen is less than 15 this is a finding.

# grep PASS_MIN_LEN /etc/login.defs

Confirm the PASS_MIN_LEN option is set to at least 15 as in the example below:

PASS_MIN_LEN		15

If this line does not exist, or is less than 15, this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so minlen=15

prior to the "password include system-auth-ac" line.

Edit /etc/login.defs to include the line:

PASS_MIN_LEN		15'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19702r554018_chk'
  tag severity: 'medium'
  tag gid: 'V-218227'
  tag rid: 'SV-218227r603259_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-19700r554019_fix'
  tag 'documentable'
  tag legacy: ['V-11947', 'SV-63903']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
