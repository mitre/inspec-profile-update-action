control 'SV-237931' do
  title 'CA VM:Secure product SECURITY CONFIG file must be restricted to appropriate personnel.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Query the CA VM:Secure product rules.

If there are product rules granting access to the disk on which the "SECURITY CONFIG" file resides for auditors, system administrators or security administrators only, this is not a finding.'
  desc 'fix', 'Create rules in the CA VM:Secure product Rules Facility that restricts access to the disk where the "SECURITY CONFIG" file resides to auditors, system administrators or security administrators only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41141r858995_chk'
  tag severity: 'medium'
  tag gid: 'V-237931'
  tag rid: 'SV-237931r858997_rule'
  tag stig_id: 'IBMZ-VM-000830'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-41100r858996_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['SV-93615', 'V-78909']
  tag cci: ['CCI-000366', 'CCI-001493']
  tag nist: ['CM-6 b', 'AU-9 a']
end
