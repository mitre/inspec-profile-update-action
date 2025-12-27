control 'SV-234622' do
  title 'The UEM server must be configured with the periodicity of the following commands to the agent of six hours or less:  - query connectivity status - query the current version of the managed device firmware/software - query the current version of installed mobile applications - read audit logs kept by the managed device.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to applications performing security functions and the applications performing security function verification/testing. 

Satisfies:FAU_NET_EXT.1.1, FMT_SMF.1.1(2) c.3 
Reference:PP-MDM-411057'
  desc 'check', 'Verify the UEM server is configured with the periodicity of the following commands to the agent of six hours or less: 
- query connectivity status;
- query the current version of the managed device firmware/software;
- query the current version of installed mobile applications;
- read audit logs kept by the managed device.

If the UEM server is not configured with the periodicity of the following commands to the agent of six hours or less: 
- query connectivity status;
- query the current version of the managed device firmware/software;
- query the current version of installed mobile applications;
- read audit logs kept by the managed device,
this is a finding.'
  desc 'fix', 'Configure the UEM server with the periodicity of the following commands to the agent of six hours or less: 
- query connectivity status;
- query the current version of the managed device firmware/software;
- query the current version of installed mobile applications;
- read audit logs kept by the managed device.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37807r851696_chk'
  tag severity: 'medium'
  tag gid: 'V-234622'
  tag rid: 'SV-234622r879843_rule'
  tag stig_id: 'SRG-APP-000472-UEM-000347'
  tag gtitle: 'SRG-APP-000472'
  tag fix_id: 'F-37772r878111_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
