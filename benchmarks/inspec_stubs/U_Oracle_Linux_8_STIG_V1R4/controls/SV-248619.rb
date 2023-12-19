control 'SV-248619' do
  title 'OL 8 must prevent special devices on non-root local partitions.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access. The only legitimate location for device files is the /dev directory located on the root partition.'
  desc 'check', %q(Verify all non-root local partitions are mounted with the "nodev" option with the following command:

$ sudo mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'

If any output is produced, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on all non-root local partitions.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52053r779421_chk'
  tag severity: 'medium'
  tag gid: 'V-248619'
  tag rid: 'SV-248619r779423_rule'
  tag stig_id: 'OL08-00-010580'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52007r779422_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
