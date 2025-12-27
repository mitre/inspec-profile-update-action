control 'SV-30081' do
  title 'Dial-out access from the Hardware Management Console Remote Support Facility (RSF) must be disabled for all classified systems.'
  desc 'This feature will not be activated for any classified systems. Allowing dial-out access from the Hardware Management Console could impact the integrity of the environment by enabling the possible introduction of spyware or other malicious code.'
  desc 'check', 'Have the Systems Administrator or Systems Programmer validate that dial-out access from the Hardware Management Console is not activated for any classified systems.

Note: This can be accomplished by going to the Customize Remote Service Panel on the Hardware Management Console and verifying that enable remote service is not enabled.

If this is a classified system and enable remote service is enabled, then this is a FINDING.'
  desc 'fix', 'Have the Systems Administrator or Systems Programmer validate that dial-out access from the Hardware Management Console is not activated for any classified systems.
Note: This can be accomplished by going to the Customize Remote Service Panel on the Hardware Management Console and verifying that enable remote service is not enabled.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-30381r1_chk'
  tag severity: 'high'
  tag gid: 'V-24398'
  tag rid: 'SV-30081r2_rule'
  tag stig_id: 'HMC0035'
  tag gtitle: 'HMC0035'
  tag fix_id: 'F-27161r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'EBRP-1, EBRU-1'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
