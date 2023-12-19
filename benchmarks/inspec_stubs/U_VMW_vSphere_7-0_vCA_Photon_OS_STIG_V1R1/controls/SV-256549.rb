control 'SV-256549' do
  title 'The Photon operating system must configure sshd to disable X11 forwarding.'
  desc 'X11 is an older, insecure graphics forwarding protocol. It is not used by Photon and should be disabled as a general best practice to limit attack surface area and communication channels.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i X11Forwarding

Expected result:

X11Forwarding no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "X11Forwarding" line is uncommented and set to the following:

X11Forwarding no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60224r887319_chk'
  tag severity: 'medium'
  tag gid: 'V-256549'
  tag rid: 'SV-256549r887321_rule'
  tag stig_id: 'PHTN-30-000080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60167r887320_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
