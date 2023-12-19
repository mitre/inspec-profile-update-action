control 'SV-223933' do
  title 'The CA-TSS HPBPW Control Option must be set to three days maximum.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ISPF Command enter:
TSS MODIFY STATUS

If the HPBPW Control Option value is set to (3) days maximum, this is not a finding.

If the HPBPW Control Option value is set to greater than (3) days, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the HPBPW control option setting to a maximum of 3 days.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25606r516198_chk'
  tag severity: 'medium'
  tag gid: 'V-223933'
  tag rid: 'SV-223933r877774_rule'
  tag stig_id: 'TSS0-ES-000600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25594r516199_fix'
  tag 'documentable'
  tag legacy: ['SV-107677', 'V-98573']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
