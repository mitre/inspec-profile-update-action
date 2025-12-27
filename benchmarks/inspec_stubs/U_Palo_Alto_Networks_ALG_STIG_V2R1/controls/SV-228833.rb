control 'SV-228833' do
  title 'The Palo Alto Networks security platform, if used as a TLS gateway/decryption point or VPN concentrator, must use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.  Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections.'
  desc 'check', 'If the Palo Alto Networks security platform does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS, and webmail), this is not applicable.

Use the command line interface to determine if the device is operating in FIPS mode. Enter the CLI command "show fips-mode" or the command show fips-cc (for more recent releases).

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
  tag check_id: 'C-31068r513794_chk'
  tag severity: 'medium'
  tag gid: 'V-228833'
  tag rid: 'SV-228833r557387_rule'
  tag stig_id: 'PANW-AG-000016'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-31045r513795_fix'
  tag 'documentable'
  tag legacy: ['V-62549', 'SV-77039']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
