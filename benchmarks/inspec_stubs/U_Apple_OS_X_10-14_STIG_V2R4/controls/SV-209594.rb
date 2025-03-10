control 'SV-209594' do
  title 'The macOS system must be configured to disable the tftpd service.'
  desc 'The "tftpd" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit. 

If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling ftp is one way to mitigate this risk. Administrators should be instructed to use an alternate service for data transmission that uses encryption, such as SFTP.'
  desc 'check', 'To check if the tftpd service is disabled, run the following command:

sudo launchctl print-disabled system | grep tftpd

If the results do not show the following, this is a finding:
"com.apple.tftpd" => true'
  desc 'fix', 'To disable the tftpd service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.tftpd'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9845r282264_chk'
  tag severity: 'high'
  tag gid: 'V-209594'
  tag rid: 'SV-209594r610285_rule'
  tag stig_id: 'AOSX-14-002038'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-9845r282265_fix'
  tag 'documentable'
  tag legacy: ['SV-105065', 'V-95927']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
