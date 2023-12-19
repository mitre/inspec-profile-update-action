control 'SV-257207' do
  title 'The macOS system must be configured to disable the "tftp" service.'
  desc 'The "tftp" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit.

If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling "ftp" is one way to mitigate this risk. Administrators must be instructed to use an alternate service for data transmission that uses encryption, such as SFTP.

Additionally, the "tftp" service uses UDP, which is not secure.'
  desc 'check', 'Verify the macOS system is configured to disable the tfptd service with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep com.apple.tftpd

"com.apple.tftpd" => disabled

If the results are not "com.apple.tftpd => disabled", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the "tftpd" service with the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.tftpd

The system may need to be restarted for the update to take effect.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60892r905252_chk'
  tag severity: 'high'
  tag gid: 'V-257207'
  tag rid: 'SV-257207r905254_rule'
  tag stig_id: 'APPL-13-002038'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-60833r905253_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
