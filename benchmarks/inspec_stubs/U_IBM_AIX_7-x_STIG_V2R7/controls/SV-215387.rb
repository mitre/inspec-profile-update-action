control 'SV-215387' do
  title 'The imap2 service must be disabled on AIX.'
  desc 'The imap2 service or Internet Message Access Protocol (IMAP) supports the IMAP4 remote mail access protocol. It works with sendmail and bellmail. This service should be disabled if it is not required to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^imap2[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "imap2" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'imap2' -p 'tcp'

Restart inetd:
#  refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16585r294612_chk'
  tag severity: 'medium'
  tag gid: 'V-215387'
  tag rid: 'SV-215387r508663_rule'
  tag stig_id: 'AIX7-00-003082'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16583r294613_fix'
  tag 'documentable'
  tag legacy: ['V-91405', 'SV-101503']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
