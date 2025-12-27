control 'SV-217864' do
  title 'All device files must be monitored by the system Linux Security Module.'
  desc 'If a device file carries the SELinux type "unlabeled_t", then SELinux cannot properly restrict access to the device file.'
  desc 'check', 'To check for unlabeled device files, run the following command:

# ls -RZ /dev | grep unlabeled_t

It should produce no output in a well-configured system. 

If there is output, this is a finding.'
  desc 'fix', %q(Device files, which are used for communication with important system resources, should be labeled with proper SELinux types. If any device files carry the SELinux type "unlabeled_t", investigate the cause and correct the file's context.)
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19345r376607_chk'
  tag severity: 'low'
  tag gid: 'V-217864'
  tag rid: 'SV-217864r603264_rule'
  tag stig_id: 'RHEL-06-000025'
  tag gtitle: 'SRG-OS-000324'
  tag fix_id: 'F-19343r376608_fix'
  tag 'documentable'
  tag legacy: ['V-51379', 'SV-65589']
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end
