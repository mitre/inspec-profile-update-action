control 'SV-77695' do
  title 'The SSH daemon must not permit GSSAPI authentication.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.'
  desc 'check', 'To verify the GSSAPIAuthentication setting, run the following command: 

# grep -i "^GSSAPIAuthentication" /etc/ssh/sshd_config

If there is no output or the output is not exactly "GSSAPIAuthentication no", this is a finding.'
  desc 'fix', 'To set the GSSAPIAuthentication setting, add or correct the following line in "/etc/ssh/sshd_config":

GSSAPIAuthentication no'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63939r1_chk'
  tag severity: 'low'
  tag gid: 'V-63205'
  tag rid: 'SV-77695r1_rule'
  tag stig_id: 'ESXI-06-000018'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69123r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
