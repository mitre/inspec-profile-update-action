control 'SV-223934' do
  title 'The CA-TSS INSTDATA Control Option must be set to 0.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ISPF Command enter:
TSS MODIFY STATUS

If the INSTDATA Control Option is set to NONE this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to set the INSTDATA control option value to (0) and proceed with the change.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25607r516201_chk'
  tag severity: 'medium'
  tag gid: 'V-223934'
  tag rid: 'SV-223934r561402_rule'
  tag stig_id: 'TSS0-ES-000610'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25595r516202_fix'
  tag 'documentable'
  tag legacy: ['SV-107679', 'V-98575']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
