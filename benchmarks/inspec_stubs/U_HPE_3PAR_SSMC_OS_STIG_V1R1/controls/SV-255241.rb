control 'SV-255241' do
  title 'SSMC must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'To verify that the 15-character minimum password length policy is set, do the following: 

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o long_password_policy -a status
Long password policy is enabled

If the status does not read "enabled", this is a finding.'
  desc 'fix', 'To enable and enforce the 15-character minimum password length policy, do the following: 

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o long_password_policy -a enable -f

Note: ssmcaudit user should be disabled before executing this fix procedure.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58854r869871_chk'
  tag severity: 'medium'
  tag gid: 'V-255241'
  tag rid: 'SV-255241r869873_rule'
  tag stig_id: 'SSMC-OS-010070'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-58798r869872_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
