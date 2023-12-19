control 'SV-258875' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disable X11 forwarding.'
  desc 'X11 is an older, insecure graphics forwarding protocol. It is not used by Photon and should be disabled as a general best practice to limit attack surface area and communication channels.'
  desc 'check', 'At the command line, run the following command to verify the running configuration of sshd:

# sshd -T|&grep -i X11Forwarding

Example result:

x11forwarding no

If "X11Forwarding" is not set to "no", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "X11Forwarding" line is uncommented and set to the following:

X11Forwarding no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62615r933684_chk'
  tag severity: 'medium'
  tag gid: 'V-258875'
  tag rid: 'SV-258875r933686_rule'
  tag stig_id: 'PHTN-40-000212'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62524r933685_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
