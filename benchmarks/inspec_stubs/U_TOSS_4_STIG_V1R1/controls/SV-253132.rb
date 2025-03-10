control 'SV-253132' do
  title 'TOSS must restrict exposed kernel pointer addresses access.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.'
  desc 'check', 'Verify TOSS restricts exposed kernel pointer addresses access with the following commands:

$ sudo sysctl kernel.kptr_restrict

kernel.kptr_restrict = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.'
  desc 'fix', 'Configure TOSS to restrict exposed kernel pointer addresses access by adding the following line to a file in the "/etc/sysctl.d" directory:

kernel.kptr_restrict = 1

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56585r825066_chk'
  tag severity: 'medium'
  tag gid: 'V-253132'
  tag rid: 'SV-253132r825068_rule'
  tag stig_id: 'TOSS-04-040910'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56535r825067_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
