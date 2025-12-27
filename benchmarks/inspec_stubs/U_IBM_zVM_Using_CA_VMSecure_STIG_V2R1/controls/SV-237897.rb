control 'SV-237897' do
  title 'CA VM:Secure product Rules Facility must be installed and operating.'
  desc 'Enterprise environments make account management for operating systems challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors. IBM z/VM requires an external security manager to assure proper account management.

'
  desc 'check', 'Verify an “ACCESS RULE” record exists on the system using the following command:

VMSECURE CONFIG PRODUCT

If there is no “ACCESS RULE” record, this is a finding.

Verify that CA VM:SECURE RULES can be added using the following command:

VMSECURE RULES USER

If a rules file does not open, this is a finding.'
  desc 'fix', 'Ensure the Rules Facility is installed and the Product Config file contains an “ACCESS RULES” statement.'
  impact 0.7
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41107r649529_chk'
  tag severity: 'high'
  tag gid: 'V-237897'
  tag rid: 'SV-237897r649531_rule'
  tag stig_id: 'IBMZ-VM-000010'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-41066r649530_fix'
  tag satisfies: ['SRG-OS-000001-GPOS-00001', 'SRG-OS-000080-GPOS-00048']
  tag 'documentable'
  tag legacy: ['SV-93547', 'V-78841']
  tag cci: ['CCI-000015', 'CCI-000213']
  tag nist: ['AC-2 (1)', 'AC-3']
end
