control 'SV-30531' do
  title 'Power On Reset (POR) Procedures must be documented for each system.'
  desc 'If procedures for performing PORs are not in place, it is extremely difficult to ensure overall operating system integrity'
  desc 'check', 'Review the POR procedures with the System Administrator.
 Review documentation for completeness and accuracy.

	If no documentation exists, this is a FINDING'
  desc 'fix', 'Create or refine procedures for performing PORs.'
  impact 0.3
  ref 'DPMS Target IBM HMC LIC Policy'
  tag check_id: 'C-30869r1_chk'
  tag severity: 'low'
  tag gid: 'V-24842'
  tag rid: 'SV-30531r1_rule'
  tag stig_id: 'HMCP0110'
  tag gtitle: 'HMCP0110'
  tag fix_id: 'F-27489r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Systems Programmer']
  tag ia_controls: 'COTR-1'
  tag cci: ['CCI-000904']
  tag nist: ['PE-1 a 1 (a)']
end
