control 'SV-71465' do
  title 'The operating system must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', 'Verify the operating system uses cryptographic mechanisms to protect the integrity of audit tools. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to use cryptographic mechanisms to protect the integrity of audit tools.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57205'
  tag rid: 'SV-71465r1_rule'
  tag stig_id: 'SRG-OS-000278-GPOS-00108'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-62115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
