control 'SV-234526' do
  title 'The UEM server must disable organization-defined functions, ports, protocols, and services (within the application) deemed unnecessary and/or non-secure.'
  desc 'Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.

Examples include unneeded listening ports.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure. 

Satisfies:FMT_SMF.1.1(2) Refinement b 
Reference:PP-MDM-431006'
  desc 'check', 'Verify the UEM server disables organization-defined functions, ports, protocols, and services (within the application) deemed unnecessary and/or non-secure.

If the UEM server does not disable organization-defined functions, ports, protocols, and services (within the application) deemed unnecessary and/or non-secure, this is a finding.'
  desc 'fix', 'Configure the UEM server to disable organization-defined functions, ports, protocols, and services (within the application) deemed unnecessary and/or non-secure.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37711r851596_chk'
  tag severity: 'medium'
  tag gid: 'V-234526'
  tag rid: 'SV-234526r879756_rule'
  tag stig_id: 'SRG-APP-000383-UEM-000254'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-37676r615222_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
