control 'SV-248600' do
  title 'OL 8 must have the packages required to use the hardware random number generator entropy gatherer service.'
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness. The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.  
 
The rngd service feeds random data from hardware device to kernel random device. Quality (non-predictable) random number generation is important for several security functions (i.e., ciphers).'
  desc 'check', 'Check that OL 8 has the packages required to enabled the hardware random number generator entropy gatherer service with the following command:

$ sudo yum list installed rng-tools

rng-tools.x86_64                     6.8-3.el8                        @anaconda

If the "rng-tools" package is not installed, this is a finding.'
  desc 'fix', 'Install the packages required to enabled the hardware random number generator entropy gatherer service with the following command:

$ sudo yum install rng-tools'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52034r779364_chk'
  tag severity: 'low'
  tag gid: 'V-248600'
  tag rid: 'SV-248600r779366_rule'
  tag stig_id: 'OL08-00-010472'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51988r779365_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
