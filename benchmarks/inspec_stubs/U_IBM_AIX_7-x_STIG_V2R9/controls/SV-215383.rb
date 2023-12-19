control 'SV-215383' do
  title 'The klogin daemon must be disabled on AIX.'
  desc 'The klogin service offers a higher degree of security than traditional rlogin or telnet by eliminating most clear-text password exchanges on the network. However, it is still not as secure as SSH, which encrypts all traffic. If using klogin to log in to a system, the password is not sent in clear text; however, if using "su" to another user, that password exchange is open to detection from network-sniffing programs. The recommendation is to use SSH wherever possible instead of klogin.

If the klogin service is used, use the latest Kerberos version available and make sure that all the latest patches are installed.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^klogin[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "klogin" entry by running command:  
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'klogin' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16581r294600_chk'
  tag severity: 'medium'
  tag gid: 'V-215383'
  tag rid: 'SV-215383r508663_rule'
  tag stig_id: 'AIX7-00-003078'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16579r294601_fix'
  tag 'documentable'
  tag legacy: ['V-91397', 'SV-101495']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
