control 'SV-239154' do
  title 'The Photon operating system must configure sshd to disallow Generic Security Service Application Program Interface (GSSAPI) authentication.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i GSSAPIAuthentication

Expected result:

GSSAPIAuthentication no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "GSSAPIAuthentication" line is uncommented and set to the following:

GSSAPIAuthentication no

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42365r675268_chk'
  tag severity: 'medium'
  tag gid: 'V-239154'
  tag rid: 'SV-239154r675270_rule'
  tag stig_id: 'PHTN-67-000083'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42324r675269_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
