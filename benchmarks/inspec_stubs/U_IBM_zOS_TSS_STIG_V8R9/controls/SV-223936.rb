control 'SV-223936' do
  title 'CA-TSS TEMPDS Control Option must be set to YES.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the TEMPDS Control Option value is set to TEMPDS(YES), this not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting to TEMPDS(YES), and proceed with the change.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25609r516207_chk'
  tag severity: 'medium'
  tag gid: 'V-223936'
  tag rid: 'SV-223936r877777_rule'
  tag stig_id: 'TSS0-ES-000630'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25597r516208_fix'
  tag 'documentable'
  tag legacy: ['SV-107683', 'V-98579']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
