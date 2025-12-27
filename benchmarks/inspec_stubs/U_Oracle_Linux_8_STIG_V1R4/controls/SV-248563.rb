control 'SV-248563' do
  title 'The OL 8 SSH server must be configured to use strong entropy.'
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness. The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems. 
 
The SSH implementation in OL 8 uses the OPENSSL library, which does not use high-entropy sources by default. By using the SSH_USE_STRONG_RNG environment variable, the OPENSSL random generator is reseeded from "/dev/random". This setting is not recommended on computers without the hardware random generator because insufficient entropy causes the connection to be blocked until enough entropy is available.'
  desc 'check', 'Verify the operating system SSH server uses strong entropy with the following command: 
 
$ sudo grep -i ssh_use_strong_rng /etc/sysconfig/sshd 
 
SSH_USE_STRONG_RNG=32 
 
If the "SSH_USE_STRONG_RNG" line does not equal "32" or is commented out or missing, this is a finding.'
  desc 'fix', 'Configure the operating system SSH server to use strong entropy. 
 
Add or modify the following line in the "/etc/sysconfig/sshd" file. 
 
SSH_USE_STRONG_RNG=32 
 
The SSH service must be restarted for changes to take effect.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51997r779253_chk'
  tag severity: 'low'
  tag gid: 'V-248563'
  tag rid: 'SV-248563r779255_rule'
  tag stig_id: 'OL08-00-010292'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-51951r779254_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
