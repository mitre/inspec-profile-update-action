control 'SV-239152' do
  title 'The Photon operating system must disable the debug-shell service.'
  desc 'The debug-shell service is intended to diagnose system-related boot issues with various systemctl commands. Once enabled and following a system reboot, the root shell will be available on tty9. This service must remain disabled until and unless otherwise directed by VMware support.'
  desc 'check', 'At the command line, execute the following command:

# systemctl status debug-shell.service|grep -E --color=always disabled

If the debug-shell service is not disabled, this is a finding.'
  desc 'fix', 'At the command line, execute the following commands:

# systemctl stop debug-shell.service
# systemctl disable debug-shell.service

Reboot for changes to take effect.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42363r675262_chk'
  tag severity: 'medium'
  tag gid: 'V-239152'
  tag rid: 'SV-239152r675264_rule'
  tag stig_id: 'PHTN-67-000081'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42322r675263_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
