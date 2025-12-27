control 'SV-227067' do
  title 'Automated file system mounting tools must not be enabled unless needed.'
  desc "Automated file system mounting tools may provide unprivileged users with the ability to access local media and network shares.  If this access is not necessary for the system's operation, it must be disabled to reduce the risk of unauthorized access to these resources."
  desc 'check', 'If the autofs service is needed, this vulnerability is not applicable.
Check if the autofs service is running.
# svcs svc:/system/filesystem/autofs
If the autofs service is online this is a finding.'
  desc 'fix', 'Stop and disable the autofs service.
# svcadm disable autofs'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36421r602866_chk'
  tag severity: 'low'
  tag gid: 'V-227067'
  tag rid: 'SV-227067r603265_rule'
  tag stig_id: 'GEN008440'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36385r602867_fix'
  tag 'documentable'
  tag legacy: ['SV-26965', 'V-22577']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
