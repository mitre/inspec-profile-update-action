control 'SV-215386' do
  title 'The tftp daemon must be disabled on AIX.'
  desc 'The tftp service allows remote systems to download or upload files to the tftp server without any authentication. It is therefore a service that should not run, unless needed. One of the main reasons for requiring this service to be activated is if the host is a NIM master. However, the service can be enabled and then disabled once a NIM operation has completed, rather than left running permanently.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^tftp[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "tftp" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'tftp' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16584r294609_chk'
  tag severity: 'medium'
  tag gid: 'V-215386'
  tag rid: 'SV-215386r508663_rule'
  tag stig_id: 'AIX7-00-003081'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16582r294610_fix'
  tag 'documentable'
  tag legacy: ['SV-101501', 'V-91403']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
