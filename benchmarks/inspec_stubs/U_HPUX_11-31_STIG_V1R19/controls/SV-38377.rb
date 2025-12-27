control 'SV-38377' do
  title 'Automated file system mounting tools must not be enabled unless needed.'
  desc 'Automated file system mounting tools may provide unprivileged users with the ability to access local media and network shares.  If this access is not necessary for the system’s operation, it must be disabled to reduce the risk of unauthorized access to these resources.'
  desc 'check', %q(Check /etc/rc.config.d/nfsconf for the AUTOFS automount setting. 
# cat /etc/rc.config.d/nfsconf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//' | grep -v "^#" | \
	grep -i "AUTOFS=1"

If set to 1, this is a finding. After testing, if the autofs service is required, this vulnerability is not applicable.)
  desc 'fix', 'Stop and disable the autofs service.
Edit /etc/rc.config.d/nfsconf and set the AUTOFS setting to 0.

Restart the nfs.client service.
# /usr/sbin/init.d/nfs.client stop
# /usr/sbin/init.d/nfs.client start'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36788r1_chk'
  tag severity: 'low'
  tag gid: 'V-22577'
  tag rid: 'SV-38377r1_rule'
  tag stig_id: 'GEN008440'
  tag gtitle: 'GEN008440'
  tag fix_id: 'F-32167r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
