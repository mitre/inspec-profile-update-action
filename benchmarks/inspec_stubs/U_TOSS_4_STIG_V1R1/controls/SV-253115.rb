control 'SV-253115' do
  title 'TOSS must enable the hardware random number generator entropy gatherer service.'
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness. The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.  

The rngd service feeds random data from hardware device to kernel random device. Quality (non-predictable) random number generation is important for several security functions (i.e., ciphers).'
  desc 'check', 'Check that TOSS has enabled the hardware random number generator entropy gatherer service.

Verify the rngd service is enabled and active with the following commands:

$ sudo systemctl is-enabled rngd

enabled

$ sudo systemctl is-active rngd

active

If the service is not "enable and "active", this is a finding.'
  desc 'fix', 'Start the rngd service and enable the rngd service with the following commands:

$ sudo systemctl start rngd.service

$ sudo systemctl enable rngd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56568r825015_chk'
  tag severity: 'medium'
  tag gid: 'V-253115'
  tag rid: 'SV-253115r825017_rule'
  tag stig_id: 'TOSS-04-040740'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56518r825016_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
