control 'SV-258881' do
  title 'The Photon operating system must configure Secure Shell (SSH) to ignore user-specific known_host files.'
  desc 'SSH trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled. Individual users can have a local list of trusted remote machines, which must also be ignored while disabling host-based authentication generally.'
  desc 'check', 'At the command line, run the following command to verify the running configuration of sshd:

# sshd -T|&grep -i IgnoreUserKnownHosts

Expected result:

ignoreuserknownhosts yes

If "IgnoreUserKnownHosts" is not set to "yes", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "IgnoreUserKnownHosts" line is uncommented and set to the following:

IgnoreUserKnownHosts yes

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62621r933702_chk'
  tag severity: 'medium'
  tag gid: 'V-258881'
  tag rid: 'SV-258881r935567_rule'
  tag stig_id: 'PHTN-40-000218'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62530r933703_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
