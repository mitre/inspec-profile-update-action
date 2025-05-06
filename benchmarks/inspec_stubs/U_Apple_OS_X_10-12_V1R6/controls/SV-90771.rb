control 'SV-90771' do
  title 'The OS X system must not use unencrypted FTP.'
  desc 'The "ftp" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit. 

If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling ftp is one way to mitigate this risk. Administrators should be instructed to use an alternate service for data transmission that uses encryption, such as SFTP.'
  desc 'check', 'To check if the "ftp" service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.ftpd

If the results do not show the following, this is a finding:

"com.apple.ftpd" => true'
  desc 'fix', 'To disable the "ftp" service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.ftpd

The system may need to be restarted for the update to take effect.'
  impact 0.7
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75767r1_chk'
  tag severity: 'high'
  tag gid: 'V-76083'
  tag rid: 'SV-90771r1_rule'
  tag stig_id: 'AOSX-12-000606'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-82721r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
