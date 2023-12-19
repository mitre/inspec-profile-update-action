control 'SV-224977' do
  title 'Separate, NSA-approved (Type 1) cryptography must be used to protect the directory data in transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data.'
  desc 'Directory data that is not appropriately encrypted is subject to compromise. Commercial-grade encryption does not provide adequate protection when the classification level of directory data in transit is higher than the level of the network.'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Review the organization network diagram(s) or documentation to determine the level of classification for the network(s) over which replication data is transmitted.

Determine the classification level of the Windows domain controller.

If the classification level of the Windows domain controller is higher than the level of the networks, review the organization network diagram(s) and directory implementation documentation to determine if NSA-approved encryption is used to protect the replication network traffic.

If the classification level of the Windows domain controller is higher than the level of the network traversed and NSA-approved encryption is not used, this is a finding.'
  desc 'fix', 'Configure NSA-approved (Type 1) cryptography to protect the directory data in transit for directory service implementations at a classified confidentiality level that transfer replication data through a network cleared to a lower level than the data.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26668r465833_chk'
  tag severity: 'medium'
  tag gid: 'V-224977'
  tag rid: 'SV-224977r569186_rule'
  tag stig_id: 'WN16-DC-000140'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-26656r465834_fix'
  tag 'documentable'
  tag legacy: ['SV-88035', 'V-73383']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
