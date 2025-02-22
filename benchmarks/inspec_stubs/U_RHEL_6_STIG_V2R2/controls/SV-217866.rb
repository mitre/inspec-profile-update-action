control 'SV-217866' do
  title 'The system must prevent the root account from logging in from serial consoles.'
  desc 'Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account.'
  desc 'check', "To check for serial port entries which permit root login, run the following command: 

# grep '^ttyS[0-9]' /etc/securetty

If any output is returned, then root login over serial ports is permitted. 
If root login over serial ports is permitted, this is a finding."
  desc 'fix', 'To restrict root logins on serial ports, ensure lines of this form do not appear in "/etc/securetty": 

ttyS0
ttyS1

Note:  Serial port entries are not limited to those listed above.  Any lines starting with "ttyS" followed by numerals should be removed'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19347r376613_chk'
  tag severity: 'low'
  tag gid: 'V-217866'
  tag rid: 'SV-217866r603264_rule'
  tag stig_id: 'RHEL-06-000028'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-19345r376614_fix'
  tag 'documentable'
  tag legacy: ['V-38494', 'SV-50295']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
