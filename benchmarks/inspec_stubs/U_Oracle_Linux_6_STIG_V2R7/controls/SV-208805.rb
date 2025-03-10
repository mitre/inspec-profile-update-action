control 'SV-208805' do
  title 'The system must prevent the root account from logging in from serial consoles.'
  desc 'Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account.'
  desc 'check', "To check for serial port entries which permit root login, run the following command: 

# grep '^ttyS[0-9]' /etc/securetty

If any output is returned, then root login over serial ports is permitted. 
If root login over serial ports is permitted, this is a finding."
  desc 'fix', 'To restrict root logins on serial ports, ensure lines of this form do not appear in "/etc/securetty": 

ttyS0
ttyS1

Note:  Serial port entries are not limited to those listed above.  Any lines starting with "ttyS" followed by numerals should be removed.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9058r357395_chk'
  tag severity: 'low'
  tag gid: 'V-208805'
  tag rid: 'SV-208805r793590_rule'
  tag stig_id: 'OL6-00-000028'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-9058r357396_fix'
  tag 'documentable'
  tag legacy: ['V-50725', 'SV-64931']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
