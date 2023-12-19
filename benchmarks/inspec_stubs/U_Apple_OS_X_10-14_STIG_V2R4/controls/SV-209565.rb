control 'SV-209565' do
  title 'The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'Administrator users must never log in directly as root. To assure individual accountability and prevent unauthorized access, logging in as root over a remote connection must be disabled. Administrators should only run commands as root after first authenticating with their individual user names and passwords.'
  desc 'check', 'To check if SSH has root logins enabled, run the following command:

/usr/bin/sudo /usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config

If there is no result, or the result is set to "yes", this is a finding.'
  desc 'fix', %q(To ensure that "PermitRootLogin" is disabled by sshd, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9816r282177_chk'
  tag severity: 'medium'
  tag gid: 'V-209565'
  tag rid: 'SV-209565r610285_rule'
  tag stig_id: 'AOSX-14-001100'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-9816r282178_fix'
  tag 'documentable'
  tag legacy: ['SV-105001', 'V-95863']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
