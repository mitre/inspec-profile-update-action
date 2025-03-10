control 'SV-255967' do
  title 'The Arista network device must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Verify the Arista device is running a certified version of EOS from the Arista.com website on the Support/Software Download section.

switch#show version
Arista DCS-7280SRA-48C6-F
Hardware version: 21.00
Serial number: SSJ18250372
Hardware MAC address: 7483.ef6d.86f7
System MAC address: 7483.ef6d.86f7

Software image version: 4.26.4M
Architecture: i686
Internal build version: 4.26.4M-25280047.4264M
Internal build ID: 79589245-f1f3-49b7-8bee-cbfacac004e6
Image format version: 1.0

Uptime: 2 weeks, 0 days, 9 hours and 53 minutes
Total memory: 8098984 kB
Free memory: 6155528 kB

If the Arista network device is not running an operating system release that is currently supported by Arista Networks, this is a finding.'
  desc 'fix', 'Upgrade the Arista network device to an operating system that is supported by the vendor.

Step 1: The Administrator would log on to www.arista.com/support/software-download website and choose EOS/Active Releases and choose appropriate version of EOS to download.

Step 2: Transfer the EOS-4.x.yz.swi.sha512sum to Arista network device directory "flash:".
 
Step 3: From the EOS CLI, type dir flash: to verify the file EOS-4.x.yz.swi.sha512sum is in the directory "flash:".

switch#directory flash:
EOS-4.x.yz.swi.sha512sum

Step 4: Use the command verify to verify the checksum sha512sum:

switch#verify flash: /sha512 flash:EOS-4.x.yz
checksum should match

Step 5: The file can also be verified from bash.

switch#bash
#bash
# sha512sum  /mnt/flash/EOS-4.x.yz
*note the Arista network device would not run an invalid version of EOS and if the checksum does not match, contact an Arista Representative for assistance.'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59643r882241_chk'
  tag severity: 'high'
  tag gid: 'V-255967'
  tag rid: 'SV-255967r882243_rule'
  tag stig_id: 'ARST-ND-000860'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-59586r882242_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
