control 'SV-225158' do
  title 'The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'Administrator users must never log in directly as root. To assure individual accountability and prevent unauthorized access, logging in as root over a remote connection must be disabled. Administrators should only run commands as root after first authenticating with their individual user names and passwords.'
  desc 'check', 'To check if SSH has root logins enabled, run the following command:

/usr/bin/sudo /usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config

If there is no result, or the result is set to "yes", this is a finding.'
  desc 'fix', %q(To ensure that "PermitRootLogin" is disabled by sshd, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26857r467642_chk'
  tag severity: 'medium'
  tag gid: 'V-225158'
  tag rid: 'SV-225158r610901_rule'
  tag stig_id: 'AOSX-15-001100'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-26845r467643_fix'
  tag 'documentable'
  tag legacy: ['SV-111697', 'V-102735']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
