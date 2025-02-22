control 'SV-215395' do
  title 'If automated file system mounting tool is not required on AIX, it must be disabled.'
  desc 'Automated file system mounting tools may provide unprivileged users with the ability to access local media and network shares. If this access is not necessary for the system’s operation, it must be disabled to reduce the risk of unauthorized access to these resources.'
  desc 'check', 'Determine if the system uses "automated" by using command:

# lssrc -s automountd
Subsystem         Group            PID          Status
automountd       autofs                        inoperative

If the automountd process is active, this is a finding.'
  desc 'fix', 'Disable the automated file system mounting tools. 

Empty the /etc/auto_master file.

From the command prompt, run the following command:
# stopsrc -s automountd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16593r294636_chk'
  tag severity: 'medium'
  tag gid: 'V-215395'
  tag rid: 'SV-215395r508663_rule'
  tag stig_id: 'AIX7-00-003090'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-16591r294637_fix'
  tag 'documentable'
  tag legacy: ['V-91543', 'SV-101641']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
