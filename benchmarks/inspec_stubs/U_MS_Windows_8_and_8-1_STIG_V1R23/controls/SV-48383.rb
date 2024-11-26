control 'SV-48383' do
  title 'The system must employ automated mechanisms or must have an application installed that, on an organization defined frequency  determines the state of information system components with regard to flaw remediation.'
  desc 'Organizations are required to identify information systems containing software affected by recently announced software flaws (and potential vulnerabilities resulting from those flaws) and report this information to designated organizational officials with information security responsibilities (e.g., senior information security officers, information system security managers, information systems security officers). To support this requirement, an automated process or mechanism is required.'
  desc 'check', 'Verify the organization has an automated process to scan systems for identified software flaws and vulnerabilities.  If it does not, this is a finding.'
  desc 'fix', 'Establish an automated process to scan systems for identified software flaws and vulnerabilities.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45052r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36734'
  tag rid: 'SV-48383r2_rule'
  tag stig_id: 'WN08-GE-000028'
  tag gtitle: 'WINGE-000028'
  tag fix_id: 'F-41514r1_fix'
  tag 'documentable'
  tag ia_controls: 'VIVM-1'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
