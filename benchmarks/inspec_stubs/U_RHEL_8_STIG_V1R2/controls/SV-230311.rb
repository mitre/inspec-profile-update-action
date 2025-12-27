control 'SV-230311' do
  title 'RHEL 8 must disable the kernel.core_pattern.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.'
  desc 'check', 'Verify RHEL 8 disables storing core dumps with the following commands:

$ sudo sysctl kernel.core_pattern

kernel.core_pattern = |/bin/false

If the returned line does not have a value of "|/bin/false", or a line is not returned and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to disable storing core dumps by adding the following line to a file in the "/etc/sysctl.d" directory:

kernel.core_pattern = |/bin/false

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32980r567679_chk'
  tag severity: 'medium'
  tag gid: 'V-230311'
  tag rid: 'SV-230311r627750_rule'
  tag stig_id: 'RHEL-08-010671'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32955r567680_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
