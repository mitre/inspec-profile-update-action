control 'SV-77687' do
  title 'The SSH daemon must not permit root logins.'
  desc "Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password."
  desc 'check', %q(To verify how the SSH daemon's "PermitRootLogin" option is set, run the following command: 

# grep -i "^PermitRootLogin" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitRootLogin no", this is a finding.)
  desc 'fix', 'The root user should never be allowed to log in to a system directly over a network.

Add or correct the following line in "/etc/ssh/sshd_config": 

PermitRootLogin no'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63931r1_chk'
  tag severity: 'low'
  tag gid: 'V-63197'
  tag rid: 'SV-77687r1_rule'
  tag stig_id: 'ESXI-06-000014'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
