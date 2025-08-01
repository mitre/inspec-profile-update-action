control 'SV-35072' do
  title 'The inetd.conf and xinetd.conf files must have mode 0440 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the mode of the (x)inetd.conf file and any files identified by the configuration file includedir stanza:

# find / -type f -name  inetd.conf -o -name xinetd.conf | xargs -n1 ls -lL
# grep includedir <PATH>/xinetd.conf
# ls -lL <includedir files from previous command>

If any of the above file mode are more permissive than 0440, this is a finding.'
  desc 'fix', 'Change the mode of the (x)inetd.conf file.
# chmod 0440 <file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34936r1_chk'
  tag severity: 'medium'
  tag gid: 'V-822'
  tag rid: 'SV-35072r1_rule'
  tag stig_id: 'GEN003740'
  tag gtitle: 'GEN003740'
  tag fix_id: 'F-30242r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
