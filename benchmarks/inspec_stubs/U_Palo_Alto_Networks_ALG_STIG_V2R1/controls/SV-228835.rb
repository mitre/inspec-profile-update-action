control 'SV-228835' do
  title 'The Palo Alto Networks security platform, if used as a TLS gateway/decryption point or VPN concentrator, must use NIST FIPS-validated cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.  Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).'
  desc 'check', 'If the Palo Alto Networks security platform is not used as a TLS gateway/decryption point or VPN concentrator, this is not applicable.

Use the command line interface to determine if the device is operating in FIPS mode. Enter the CLI command "show fips-mode" or the command show fips-cc (for more recent releases).'
  desc 'fix', 'If the Palo Alto Networks security platform is used as a TLS gateway/decryption point or VPN concentrator, it must use NIST FIPS-validated cryptography.

Power off the device by unplugging it from the electrical outlet.
 
Connect a console cable from the console port to a computer serial port, and use a terminal program to connect to the Palo Alto Networks device.
 
The serial parameters are 9600 baud, 8 data bits, no parity, and 1 stop bit.
 
A USB to serial adapter will be necessary if the computer does not have a serial port.

During the boot sequence, this message will appear:
"Autoboot to default partition in 5 seconds".

Enter "maint" to boot to "maint" partition.

Enter "maint" to enter maintenance mode.

Press "Enter", and the "Maintenance Recovery tool" menu will appear.

Select "Set FIPS Mode" (or select fips-cc for more recent versions) from the menu; once the device has finished rebooting, it will be in FIPS mode.

Note: This will remove all installed licenses and disable the serial port.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31070r513800_chk'
  tag severity: 'medium'
  tag gid: 'V-228835'
  tag rid: 'SV-228835r557387_rule'
  tag stig_id: 'PANW-AG-000020'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-31047r513801_fix'
  tag 'documentable'
  tag legacy: ['V-62553', 'SV-77043']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
