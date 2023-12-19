control 'SV-208804' do
  title 'The system must prevent the root account from logging in from virtual consoles.'
  desc 'Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account.'
  desc 'check', "To check for virtual console entries which permit root login, run the following command: 

# grep '^vc/[0-9]' /etc/securetty

If any output is returned, then root logins over virtual console devices is permitted. 
If root login over virtual console devices is permitted, this is a finding."
  desc 'fix', 'To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in "/etc/securetty": 

vc/1
vc/2
vc/3
vc/4

Note:  Virtual console entries are not limited to those listed above.  Any lines starting with "vc/" followed by numerals should be removed.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9057r357392_chk'
  tag severity: 'medium'
  tag gid: 'V-208804'
  tag rid: 'SV-208804r603263_rule'
  tag stig_id: 'OL6-00-000027'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-9057r357393_fix'
  tag 'documentable'
  tag legacy: ['V-50721', 'SV-64927']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
