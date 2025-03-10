control 'SV-214882' do
  title 'The macOS system must not use telnet.'
  desc 'The "telnet" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit. 

If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling telnet is one way to mitigate this risk. Administrators should be instructed to use an alternate service for remote access sessions, non-local maintenance sessions, and diagnostic communications that uses encryption, such as SSH.

'
  desc 'check', 'To check if the "telnet" service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.telnetd

If the results do not show the following, this is a finding:

"com.apple.telnetd" => true'
  desc 'fix', 'To disable the "telnet" service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.telnetd

The system may need to be restarted for the update to take effect.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16082r397218_chk'
  tag severity: 'high'
  tag gid: 'V-214882'
  tag rid: 'SV-214882r609363_rule'
  tag stig_id: 'AOSX-13-000605'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16080r397219_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag legacy: ['SV-96357', 'V-81643']
  tag cci: ['CCI-000197', 'CCI-000877', 'CCI-001453', 'CCI-002890', 'CCI-003123']
  tag nist: ['IA-5 (1) (c)', 'MA-4 c', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
