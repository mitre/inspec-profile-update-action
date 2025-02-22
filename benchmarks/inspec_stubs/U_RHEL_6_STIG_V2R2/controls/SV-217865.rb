control 'SV-217865' do
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
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19346r376610_chk'
  tag severity: 'medium'
  tag gid: 'V-217865'
  tag rid: 'SV-217865r603264_rule'
  tag stig_id: 'RHEL-06-000027'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-19344r376611_fix'
  tag 'documentable'
  tag legacy: ['V-38492', 'SV-50293']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
