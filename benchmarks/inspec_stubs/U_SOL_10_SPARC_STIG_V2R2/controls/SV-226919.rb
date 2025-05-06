control 'SV-226919' do
  title 'The rexec daemon must not be running.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', '# svcs rexec
If the service is enabled, this is a finding.'
  desc 'fix', '# svcadm disable rexec
# svcadm refresh inetd'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29081r485053_chk'
  tag severity: 'high'
  tag gid: 'V-226919'
  tag rid: 'SV-226919r603265_rule'
  tag stig_id: 'GEN003840'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29069r485054_fix'
  tag 'documentable'
  tag legacy: ['V-4688', 'SV-27438']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
