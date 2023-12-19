control 'SV-215322' do
  title 'AIX must disable /usr/bin/rcp,
/usr/bin/rlogin,
/usr/bin/rsh, /usr/bin/rexec and /usr/bin/telnet commands.'
  desc 'The listed applications permit the transmission of passwords in plain text.  Alternative applications such as SSH, which encrypt data, should be use instead.'
  desc 'check', "From the command prompt, execute the following commands:
# ls -l /usr/bin/rcp | awk '{print $1}'
# ls -l /usr/bin/rlogin | awk '{print $1}'
# ls -l /usr/bin/rsh | awk '{print $1}'
# ls -l /usr/bin/telnet | awk '{print $1}'
# ls -l /usr/bin/rexec | awk '{print $1}'

Each of the above commands should return with the following permissions:
 ----------

If the permissions are more permissive, this is a finding."
  desc 'fix', 'Use the chmod command to remove all permissions on these commands: 
# chmod ugo= /usr/bin/rcp
# chmod ugo= /usr/bin/rlogin
# chmod ugo= /usr/bin/rsh
# chmod ugo= /usr/bin/rexec
# chmod ugo= /usr/bin/telnet'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16520r294417_chk'
  tag severity: 'high'
  tag gid: 'V-215322'
  tag rid: 'SV-215322r877396_rule'
  tag stig_id: 'AIX7-00-003005'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16518r294418_fix'
  tag 'documentable'
  tag legacy: ['SV-101393', 'V-91295']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
