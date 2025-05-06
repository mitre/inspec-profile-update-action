control 'SV-30055' do
  title 'Processor Resource/Systems Manager (PR/SM) must not allow unrestricted issuing of control program commands.'
  desc 'Unrestricted control over the issuing of system commands by a Logical Partition could result in unauthorized data access and inadvertent updates. This could result in severe damage to system resources.'
  desc 'check', 'Using the Hardware Management Console, verify that the Logical Partitions cannot issue control program commands to another Logical Partition.  Use the PR/SM panel, known as the Security Definitions Page, to do this.  The Cross Partition Control option must be turned off.

NOTE:  The default is that the Cross Partition Control option is turned off.

If Processor Resource/Systems Manager (PR/SM) allows unrestricted issuing of control program commands then this  is a FINDING'
  desc 'fix', 'Review the Security Definition parameters specified under PR/SM, and turn off the Cross Partition Control option.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-3642r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24380'
  tag rid: 'SV-30055r2_rule'
  tag stig_id: 'HLP0030'
  tag gtitle: 'HLP0030'
  tag fix_id: 'F-2347r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000226']
  tag nist: ['AC-6 (4)']
end
