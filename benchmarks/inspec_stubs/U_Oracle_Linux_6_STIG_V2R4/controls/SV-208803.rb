control 'SV-208803' do
  title 'All device files must be monitored by the system Linux Security Module.'
  desc 'If a device file carries the SELinux type "unlabeled_t", then SELinux cannot properly restrict access to the device file.'
  desc 'check', 'To check for unlabeled device files, run the following command:

# ls -RZ /dev | grep unlabeled_t

It should produce no output in a well-configured system.

If there is output, this is a finding.'
  desc 'fix', %q(Device files, which are used for communication with important system resources, should be labeled with proper SELinux types. If any device files carry the SELinux type "unlabeled_t", investigate the cause and correct the file's context.)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9056r357389_chk'
  tag severity: 'low'
  tag gid: 'V-208803'
  tag rid: 'SV-208803r603263_rule'
  tag stig_id: 'OL6-00-000025'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9056r357390_fix'
  tag 'documentable'
  tag legacy: ['SV-73801', 'V-59371']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
