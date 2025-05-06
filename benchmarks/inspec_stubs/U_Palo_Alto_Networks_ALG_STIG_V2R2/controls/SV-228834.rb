control 'SV-228834' do
  title 'The Palo Alto Networks security platform that stores secret or private keys must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder. 

Private key data associated with software certificates is required to be generated and protected in at least a FIPS 140-2 Level 1 validated cryptographic module."
  desc 'check', 'Use the command line interface to determine if the device is operating in FIPS mode.

If fips-mode or fips-cc is set to "off", this is a finding.'
  desc 'fix', 'To configure the Palo Alto Networks security platform to operate in FIPS mode:

Power off the device by unplugging it from the electrical outlet.
 
Connect a console cable from the console port to a computer serial port, and use a terminal program to connect to the Palo Alto Networks device.
 
The serial parameters are 9600 baud, 8 data bits, no parity, and 1 stop bit.
 
A USB to serial adapter will be necessary if the computer does not have a serial port.

During the boot sequence, this message will appear:

"Autoboot to default partition in 5 seconds".

Enter "maint" to boot to "maint" partition.

Enter "maint" to enter maintenance mode.

Press "Enter", and the "Maintenance Recovery tool" menu will appear.

Select "Set FIPS Mode" (or fips-cc for later versions) from the menu; once the device has finished rebooting, it will be in FIPS mode.

Note: This will remove all installed licenses and disable the serial port.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31069r513797_chk'
  tag severity: 'medium'
  tag gid: 'V-228834'
  tag rid: 'SV-228834r557387_rule'
  tag stig_id: 'PANW-AG-000017'
  tag gtitle: 'SRG-NET-000062-ALG-000092'
  tag fix_id: 'F-31046r513798_fix'
  tag 'documentable'
  tag legacy: ['SV-77041', 'V-62551']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
