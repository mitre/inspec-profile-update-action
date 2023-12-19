control 'SV-215259' do
  title 'AIX ftpd daemon must not be running.'
  desc 'The ftp service is used to transfer files from or to a remote machine. The username and passwords are passed over the network in clear text and therefore insecurely. Remote file transfer, if required, should be facilitated through SSH.'
  desc 'check', 'Determine if the "ftp" daemon is running by running the following command:
# grep "^ftp[[:blank:]]" /etc/inetd.conf

If an entry is returned like the following line, the "ftp" daemon is running:
ftp stream tcp6 nowait root /usr/sbin/ftpd ftpd 

If the above grep command returned a line that contains "ftpd", this is a finding.'
  desc 'fix', %q(Disable "ftp" daemon entry in "/etc/inetd.conf" using command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'ftp' -p 'tcp6'

Reload the inetd process:
# refresh -s inetd)
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16457r294228_chk'
  tag severity: 'high'
  tag gid: 'V-215259'
  tag rid: 'SV-215259r877396_rule'
  tag stig_id: 'AIX7-00-002060'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16455r294229_fix'
  tag 'documentable'
  tag legacy: ['V-91307', 'SV-101405']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
