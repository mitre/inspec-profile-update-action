control 'SV-38832' do
  title 'Automated file system mounting tools must not be enabled unless needed.'
  desc 'Automated file system mounting tools may provide unprivileged users with the ability to access local media and network shares.  If this access is not necessary for the system’s operation, it must be disabled to reduce the risk of unauthorized access to these resources.'
  desc 'check', 'Determine if the system uses automated file system mounting tools (such as autofs or automount).  AIX can use automount facility.

#ps -ef | grep -v grep | grep automount 

If the automount process is running, this is a finding.'
  desc 'fix', 'Disable the automated file system mounting tools.
Empty the /etc/auto_master file 

kill automount
kill < pid of automount >'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37093r1_chk'
  tag severity: 'low'
  tag gid: 'V-22577'
  tag rid: 'SV-38832r1_rule'
  tag stig_id: 'GEN008440'
  tag gtitle: 'GEN008440'
  tag fix_id: 'F-32359r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
