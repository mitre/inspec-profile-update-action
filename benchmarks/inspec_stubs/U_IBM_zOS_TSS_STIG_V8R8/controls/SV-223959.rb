control 'SV-223959' do
  title 'The CA-TSS SUBACID Control Option must be set to U,8.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.'
  desc 'check', 'From this ISPF Command Shell enter:
TSS MODIFY STATUS

If the SUBACID Control Option values are NOT set to "SUBACID(U,8)", this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting to "SUBACID(U,8)", and proceed with the change.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25632r516276_chk'
  tag severity: 'medium'
  tag gid: 'V-223959'
  tag rid: 'SV-223959r856096_rule'
  tag stig_id: 'TSS0-ES-000860'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-25620r516277_fix'
  tag 'documentable'
  tag legacy: ['SV-107729', 'V-98625']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
