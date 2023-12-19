control 'SV-228877' do
  title 'The Palo Alto Networks security platform, if used for TLS/SSL decryption, must use NIST FIPS-validated cryptography to implement encryption.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'If the Palo Alto Networks security platform is not used for TLS/SSL decryption, this is not applicable.

Use the command line interface to determine if the device is operating in FIPS mode. Enter the CLI command "show fips-mode" or the command show fips-cc (for more recent releases).

If fips mode is set to off, this is a finding.'
  desc 'fix', 'Power off the device by unplugging it from the electrical outlet.
 
Connect a console cable from the console port to a computer serial port, and use a terminal program to connect to the Palo Alto Networks device.
 
The serial parameters are "9600 baud", "8 data bits", "no parity", and "1 stop bit".
 
A USB to serial adapter will be necessary if the computer does not have a serial port.

During the boot sequence, this message will appear:

Autoboot to default partition in 5 seconds.

Enter "maint" to boot to "maint" partition.

Enter "maint" to enter maintenance mode.

Press "Enter", and the "Maintenance Recovery tool" menu will appear.

Select "Set FIPS Mode" (or fips-cc for later versions) from the menu; once the device has finished rebooting, it will be in FIPS mode.

Note: This will remove all installed licenses and disable the serial port.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31112r513926_chk'
  tag severity: 'medium'
  tag gid: 'V-228877'
  tag rid: 'SV-228877r831618_rule'
  tag stig_id: 'PANW-AG-000143'
  tag gtitle: 'SRG-NET-000510-ALG-000111'
  tag fix_id: 'F-31089r513927_fix'
  tag 'documentable'
  tag legacy: ['SV-77125', 'V-62635']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
