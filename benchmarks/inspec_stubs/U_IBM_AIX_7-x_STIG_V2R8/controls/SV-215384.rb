control 'SV-215384' do
  title 'The kshell daemon must be disabled on AIX.'
  desc 'The kshell service offers a higher degree of security than traditional rsh services. However, it still does not use encrypted communications. The recommendation is to use SSH wherever possible instead of kshell.

If the kshell service is used, you should use the latest Kerberos version available and must make sure that all the latest patches are installed.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^kshell[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "kshell" entry by running command:  
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'kshell' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16582r294603_chk'
  tag severity: 'medium'
  tag gid: 'V-215384'
  tag rid: 'SV-215384r508663_rule'
  tag stig_id: 'AIX7-00-003079'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16580r294604_fix'
  tag 'documentable'
  tag legacy: ['SV-101497', 'V-91399']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
