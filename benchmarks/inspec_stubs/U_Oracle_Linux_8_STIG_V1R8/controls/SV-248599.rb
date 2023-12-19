control 'SV-248599' do
  title 'OL 8 must enable the hardware random number generator entropy gatherer service.'
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness. The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.  
 
The rngd service feeds random data from hardware device to kernel random device. Quality (nonpredictable) random number generation is important for several security functions (i.e., ciphers).'
  desc 'check', 'Note: For OL versions 8.4 and above running with kernel FIPS mode enabled as specified by OL08-00-010020, this requirement is Not Applicable.

Check that OL 8 has enabled the hardware random number generator entropy gatherer service.

Verify the rngd service is enabled and active with the following commands: 
 
     $ sudo systemctl is-enabled rngd 
      enabled 
 
     $ sudo systemctl is-active rngd 
     active 
 
If the service is not "enabled" and "active", this is a finding.'
  desc 'fix', 'Start the rngd service and enable it with the following commands: 
 
     $ sudo systemctl start rngd.service 
 
     $ sudo systemctl enable rngd.service'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52033r928552_chk'
  tag severity: 'low'
  tag gid: 'V-248599'
  tag rid: 'SV-248599r928553_rule'
  tag stig_id: 'OL08-00-010471'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51987r917909_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
