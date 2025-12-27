control 'SV-239190' do
  title 'The Photon operating system must protect sshd configuration from unauthorized access.'
  desc 'The sshd_config file contains all the configuration items for sshd. Incorrect or malicious configuration of sshd can allow unauthorized access to the system, insecure communication, limited forensic trail, etc.'
  desc 'check', 'At the command line, execute the following command:

# stat -c "%n permissions are %a and owned by %U:%G" /etc/ssh/sshd_config

Expected result:

/etc/ssh/sshd_config permissions are 600 and owned by root:root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, execute the following commands:

# chmod 600 /etc/ssh/sshd_config
# chown root:root /etc/ssh/sshd_config'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42401r675376_chk'
  tag severity: 'medium'
  tag gid: 'V-239190'
  tag rid: 'SV-239190r675378_rule'
  tag stig_id: 'PHTN-67-000119'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42360r675377_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
