control 'SV-234246' do
  title 'The UEM Agent must perform the following functions: 

-enroll in management

-configure whether users can unenroll from management

-configure periodicity of reachability events.'
  desc 'Access control of mobile devices to DoD sensitive information or access to DoD networks must be controlled so that DoD data will not be compromised. The primary method of access control of mobile devices is via enrollment of authorized mobile devices on the UEM server. Therefore, the UEM server must have the capability to enforce a policy for this control.

'
  desc 'check', 'Verify the UEM Agent performs the following functions: 
-Enroll in management
-Configure whether users can unenroll from management
-Configure periodicity of reachability events.

If the UEM Agent does not perform the following functions: 
-Enroll in management
-Configure whether users can unenroll from management
-Configure periodicity of reachability event 
this is a finding.'
  desc 'fix', 'Configure the UEM Agent to perform the following functions: 
-Enroll in management
-Configure whether users can unenroll from management
-Configure periodicity of reachability events.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37431r617392_chk'
  tag severity: 'medium'
  tag gid: 'V-234246'
  tag rid: 'SV-234246r617392_rule'
  tag stig_id: 'SRG-APP-000516-UEM-100010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37396r612045_fix'
  tag satisfies: ['FMT_SMF_EXT.4.2']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
