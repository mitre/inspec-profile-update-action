control 'SV-214877' do
  title 'The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'Administrators must never log in directly as root. To assure individual accountability and prevent unauthorized access, logging in as root over a remote connection must be disabled. Administrators should only run commands as root after first authenticating with their individual user names and passwords.'
  desc 'check', 'To check if SSH has root logins enabled, run the following command:

/usr/bin/sudo /usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config

If there is no result, or the result is set to "yes", this is a finding.'
  desc 'fix', %q(To ensure that "PermitRootLogin" is disabled by sshd, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16077r397203_chk'
  tag severity: 'medium'
  tag gid: 'V-214877'
  tag rid: 'SV-214877r609363_rule'
  tag stig_id: 'AOSX-13-000565'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-16075r397204_fix'
  tag 'documentable'
  tag legacy: ['SV-96347', 'V-81633']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
