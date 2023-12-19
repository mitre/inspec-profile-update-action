control 'SV-207449' do
  title 'The VMM must provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all VMM components, based on all selectable event criteria in near real time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve VMM resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting.'
  desc 'check', 'Verify the VMM provides the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all VMM components, based on all selectable event criteria in near real time.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all VMM components, based on all selectable event criteria in near real time.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7706r365757_chk'
  tag severity: 'medium'
  tag gid: 'V-207449'
  tag rid: 'SV-207449r877036_rule'
  tag stig_id: 'SRG-OS-000337-VMM-001190'
  tag gtitle: 'SRG-OS-000337'
  tag fix_id: 'F-7706r365758_fix'
  tag 'documentable'
  tag legacy: ['SV-71359', 'V-57099']
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
