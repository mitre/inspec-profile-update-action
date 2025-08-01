control 'SV-214869' do
  title 'The macOS system must unload tftpd.'
  desc 'The "tftp" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit. 

If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling ftp is one way to mitigate this risk. Administrators should be instructed to use an alternate service for data transmission that uses encryption, such as SFTP.

Additionally, the "tftp" service uses UDP, which is not secure.'
  desc 'check', 'To check if the "tfptd" service is disabled, run the following command:

sudo launchctl print-disabled system | grep tftp

If "com.apple.tftp" is not set to "true", this is a finding.'
  desc 'fix', 'To disable the "tfpd" service, run the following command:

sudo launchctl unload -w /System/Library/LaunchDaemons/tftp.plist'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16069r397179_chk'
  tag severity: 'high'
  tag gid: 'V-214869'
  tag rid: 'SV-214869r609363_rule'
  tag stig_id: 'AOSX-13-000555'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16067r397180_fix'
  tag 'documentable'
  tag legacy: ['SV-96331', 'V-81617']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
