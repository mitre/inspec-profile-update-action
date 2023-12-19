control 'SV-215372' do
  title 'The uucp (UNIX to UNIX Copy Program) daemon must be disabled on AIX.'
  desc 'This service facilitates file copying between networked servers.

The uucp (UNIX to UNIX Copy Program), service allows users to copy files between networked machines. Unless an application or process requires UUCP this should be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^uucp[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "uucp" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'uucp' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16570r294567_chk'
  tag severity: 'medium'
  tag gid: 'V-215372'
  tag rid: 'SV-215372r508663_rule'
  tag stig_id: 'AIX7-00-003067'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16568r294568_fix'
  tag 'documentable'
  tag legacy: ['V-91373', 'SV-101471']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
