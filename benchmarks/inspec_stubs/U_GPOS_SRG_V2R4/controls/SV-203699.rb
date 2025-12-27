control 'SV-203699' do
  title 'The operating system must provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting.'
  desc 'check', 'Verify the operating system provides the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3824r793153_chk'
  tag severity: 'medium'
  tag gid: 'V-203699'
  tag rid: 'SV-203699r793163_rule'
  tag stig_id: 'SRG-OS-000337-GPOS-00129'
  tag gtitle: 'SRG-OS-000337'
  tag fix_id: 'F-3824r375045_fix'
  tag 'documentable'
  tag legacy: ['SV-71499', 'V-57239']
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
