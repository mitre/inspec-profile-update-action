control 'SV-223935' do
  title 'The CA-TSS OPTIONS Control Option must include option 4 at a minimum.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the OPTIONS Control Option contains at a minimum option number (4), this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified following and proceed with the change.

The OPTIONS Control Option must contain at a minimum option number (4).

Example TSS PARMFILE Control Option entry:
OPTIONS(4,5,6,12,14)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25608r516204_chk'
  tag severity: 'medium'
  tag gid: 'V-223935'
  tag rid: 'SV-223935r877776_rule'
  tag stig_id: 'TSS0-ES-000620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25596r516205_fix'
  tag 'documentable'
  tag legacy: ['SV-107681', 'V-98577']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
