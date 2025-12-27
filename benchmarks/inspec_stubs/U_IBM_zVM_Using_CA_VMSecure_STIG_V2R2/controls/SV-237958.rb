control 'SV-237958' do
  title 'CA VM:Secure product DASD CONFIG file must be restricted to appropriate personnel.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'Query the CA VM:Secure product rules.

If there are product rules granting access to the disk on which the "DASD CONFIG" file resides for system administrators or DASD administrators only, this is not a finding.'
  desc 'fix', 'Create rules in the CA VM:Secure product Rules Facility that restricts access to the disk where the "DASD CONFIG" file resides to system administrators or DASD administrators only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41168r859048_chk'
  tag severity: 'medium'
  tag gid: 'V-237958'
  tag rid: 'SV-237958r859050_rule'
  tag stig_id: 'IBMZ-VM-001230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41127r859049_fix'
  tag 'documentable'
  tag legacy: ['SV-93669', 'V-78963']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
