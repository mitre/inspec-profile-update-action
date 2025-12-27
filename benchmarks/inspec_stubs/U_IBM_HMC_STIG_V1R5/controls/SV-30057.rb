control 'SV-30057' do
  title 'On Classified Systems the Processor Resource/Systems Manager (PR/SM) must not allow access to system complex data.'
  desc 'Allowing unrestricted access to all Logical Partition data could result in the possibility of unauthorized access and updating of data. This could also impact the integrity of the processing environment.'
  desc 'check', 'Have the Systems Administrator or Systems Programmer use the Hardware Management Console; to verify that the classified Logical Partition system data cannot be viewed by other Logical Partitions. 

Use the Security Definitions Panel to do this.  The Global Performance Data Control option must be turned off.

NOTE:	The default is that the Global Performance Data Control option is turned off.

If  the PR/SM allows access to system complex data then, this is a FINDING.'
  desc 'fix', 'Have the Systems Administrator or Systems Programmer use the Hardware Management Console, to verify that the classified Logical Partition system data cannot be viewed by other Logical Partitions. 

Use the Security Definitions Panel to do this.  The Global Performance Data Control option must be turned off.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-3644r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24382'
  tag rid: 'SV-30057r2_rule'
  tag stig_id: 'HLP0050'
  tag gtitle: 'HLP0050'
  tag fix_id: 'F-2349r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
