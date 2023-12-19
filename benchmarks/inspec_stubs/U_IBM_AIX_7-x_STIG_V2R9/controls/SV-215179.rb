control 'SV-215179' do
  title 'AIX must use the SSH server to implement replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the operating system. Authentication sessions between the authenticator and the operating system validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A privileged account is any information system account with authorizations of a privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

'
  desc 'check', 'Run the following command to check if SSH server package is installed:

# lslpp -i |grep -i ssh
 openssh.base.server 6.0.0.6201

If package "openssh.base.server" is not installed, this is a finding.

Run the following command to check if SSH daemon is running:

# lssrc -s sshd

The above command should yield the following output:
Subsystem         Group            PID          Status 
 sshd             ssh              4325532            active

If the "Status" is not "active", this is a finding.'
  desc 'fix', 'If the SSH server package is not installed, install "openssh.base.server" package from AIX DVD Volume 1 using the following command (assuming that the DVD device is /dev/cd0):
# installp -aXYgd /dev/cd0 -e /tmp/install.log openssh.base.server

After the installation, set up the SSH server accordingly.

If the SSH daemon is not running, run the following command to start it:
# startsrc -s sshd'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16377r293988_chk'
  tag severity: 'high'
  tag gid: 'V-215179'
  tag rid: 'SV-215179r853452_rule'
  tag stig_id: 'AIX7-00-001012'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag fix_id: 'F-16375r293989_fix'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag legacy: ['V-91429', 'SV-101527']
  tag cci: ['CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']
end
