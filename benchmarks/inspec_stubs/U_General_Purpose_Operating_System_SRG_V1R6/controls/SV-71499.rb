control 'SV-71499' do
  title 'The operating system must provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting.'
  desc 'check', 'Verify the operating system provides the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57239'
  tag rid: 'SV-71499r1_rule'
  tag stig_id: 'SRG-OS-000337-GPOS-00129'
  tag gtitle: 'SRG-OS-000337-GPOS-00129'
  tag fix_id: 'F-62173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
