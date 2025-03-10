control 'SV-207431' do
  title 'The VMM must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step towards ensuring the integrity of audit data. Audit data includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit VMM activity. 

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit VMM activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools for the purpose of providing the capability to hide or erase system activity from the audit logs. 

To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', 'Verify the VMM uses cryptographic mechanisms to protect the integrity of audit tools.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use cryptographic mechanisms to protect the integrity of audit tools.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7688r365703_chk'
  tag severity: 'medium'
  tag gid: 'V-207431'
  tag rid: 'SV-207431r379333_rule'
  tag stig_id: 'SRG-OS-000278-VMM-001000'
  tag gtitle: 'SRG-OS-000278'
  tag fix_id: 'F-7688r365704_fix'
  tag 'documentable'
  tag legacy: ['V-57063', 'SV-71323']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
