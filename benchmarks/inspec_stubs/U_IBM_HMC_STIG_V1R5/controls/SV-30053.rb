control 'SV-30053' do
  title 'On Classified Systems, Logical Partition must be restricted with read/write access to only its own IOCDS.'
  desc 'Unrestricted control over the IOCDS files could result in unauthorized updates and impact the configuration of the environment by allowing unauthorized access to a restricted resource. This could severely damage the integrity of the environment and the system resources.'
  desc 'check', 'Using the Hardware Management Console, verify that a logical partition cannot read or write to any IOCDS.  Use the Security Definitions Page panel to do this by checking to see if the Input/Output (I/O) Configuration Control option has been turned on.

   NOTE:	The default is applicable to only classified systems.

Confirm whether or not the I/O Configuration Control option is checked.

If the Logical Partition is not restricted with read/write access to only its own IOCDS, this is a FINDING.'
  desc 'fix', 'Review the Security Definition parameters specified under Processor Resource/Systems Manager (PR/SM).
Verify and implement the correct settings.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-3266r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24379'
  tag rid: 'SV-30053r2_rule'
  tag stig_id: 'HLP0020'
  tag gtitle: 'HLP0020'
  tag fix_id: 'F-2346r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
