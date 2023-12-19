control 'SV-230786' do
  title 'The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'Administrator users must never log in directly as root. To assure individual accountability and prevent unauthorized access, logging in as root over a remote connection must be disabled. Administrators should only run commands as root after first authenticating with their individual user names and passwords.'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

To check if SSH has root logins enabled, run the following command:

/usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config

If there is no result, or the result is set to "yes", this is a finding.'
  desc 'fix', %q(To ensure that "PermitRootLogin" is disabled by sshd, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33731r607245_chk'
  tag severity: 'medium'
  tag gid: 'V-230786'
  tag rid: 'SV-230786r599842_rule'
  tag stig_id: 'APPL-11-001100'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-33704r607246_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
