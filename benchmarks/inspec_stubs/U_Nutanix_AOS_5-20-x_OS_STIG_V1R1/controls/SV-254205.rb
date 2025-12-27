control 'SV-254205' do
  title 'Nutanix AOS must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the operating system. Authentication sessions between the authenticator and the operating system validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A privileged account is any information system account with authorizations of a privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

'
  desc 'check', 'Confirm Nutanix AOS has SSH loaded and active.

$ sudo systemctl status sshd
sshd.service - OpenSSH server daemon
Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago
Main PID: 1348 (sshd)
CGroup: /system.slice/sshd.service
1053 /usr/sbin/sshd -D

If "sshd" does not show a status of "active" and "running", this is a finding.

If the "SSH server" package is not installed, this is a finding.'
  desc 'fix', 'Configure SSH on Nutanix AOS by running the following command:

$ sudo salt-call state.sls security/CVM/sshdCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57690r846701_chk'
  tag severity: 'medium'
  tag gid: 'V-254205'
  tag rid: 'SV-254205r846703_rule'
  tag stig_id: 'NUTX-OS-001190'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag fix_id: 'F-57641r846702_fix'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag cci: ['CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']
end
