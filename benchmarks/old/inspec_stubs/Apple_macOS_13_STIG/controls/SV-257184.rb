control 'SV-257184' do
  title 'The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'Administrator users must never log in directly as root. To assure individual accountability and prevent unauthorized access, logging in as root over a remote connection must be disabled. Administrators must only run commands as root after first authenticating with their individual usernames and passwords.'
  desc 'check', 'If SSH is not being used, this is not applicable.

Verify the macOS system is configured to disable root logins over SSH with the following command:

/usr/bin/grep -r ^PermitRootLogin /etc/ssh/sshd_config*

If there is no result, or the result is set to "yes", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', "Configure the macOS system to disable root logins over SSH with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60869r905183_chk'
  tag severity: 'medium'
  tag gid: 'V-257184'
  tag rid: 'SV-257184r905185_rule'
  tag stig_id: 'APPL-13-001100'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-60810r905184_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
