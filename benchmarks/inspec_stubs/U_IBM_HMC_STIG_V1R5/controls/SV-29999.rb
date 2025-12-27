control 'SV-29999' do
  title 'The Hardware Management Console must be located in a secure location.'
  desc 'The Hardware Management Console is used to perform Initial Program Load (IPLs) and control the Processor Resource/System Manager (PR/SM). If the Hardware Management Console is not located in a secure location, unauthorized personnel can bypass security, access the system, and alter the environment. This can lead to loss of secure operations if not corrected immediately.'
  desc 'check', 'Verify the location of the Hardware Management Console.

It should be located in a controlled area.
Access to it should be restricted.

If the Hardware Management Console is not located in a secure location this is a FINDING.'
  desc 'fix', 'Move the Hardware Management Console to a secure location and implement access controls for authorized personnel.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-2873r1_chk'
  tag severity: 'high'
  tag gid: 'V-24345'
  tag rid: 'SV-29999r2_rule'
  tag stig_id: 'HMC0010'
  tag gtitle: 'HMC0010'
  tag fix_id: 'F-2339r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager', 'Security Manager', 'Systems Programmer']
  tag ia_controls: 'PECF-1, PECF-2, PEPF-1, PEPF-2'
  tag cci: ['CCI-002916']
  tag nist: ['PE-3 a 2']
end
