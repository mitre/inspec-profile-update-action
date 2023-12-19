control 'SV-38750' do
  title 'The /etc/ftpaccess.ctl file must exist.'
  desc 'The ftpaccess.ctl  file contains options for the ftp daemon, such as herald, motd, user access,  and permissions to files and directories. If the ftpaccess.ctl file does not exist, the ftpd process will not display any warning banners, and permissions will only be enforced using basic UNIX permissions.'
  desc 'fix', 'Create a /etc/ftpaccess.ctl file.
#touch /etc/ftpaccess.ctl

Add at least the herald: /path to login banner to the /etc/ftpaccess.ctl file.

#vi /etc/ftpaccess.ctl'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29519'
  tag rid: 'SV-38750r1_rule'
  tag stig_id: 'GEN000000-AIX0310'
  tag gtitle: 'GEN000000-AIX0310'
  tag fix_id: 'F-33077r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
