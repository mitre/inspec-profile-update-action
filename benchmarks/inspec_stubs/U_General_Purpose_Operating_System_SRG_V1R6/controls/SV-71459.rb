control 'SV-71459' do
  title 'The operating system must notify system administrators and ISSOs when accounts are disabled.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves.  Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system notifies System Administrators and Information System Security Officers when accounts are disabled. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to notify System Administrators and Information System Security Officers when accounts are disabled.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57771r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57199'
  tag rid: 'SV-71459r2_rule'
  tag stig_id: 'SRG-OS-000276-GPOS-00106'
  tag gtitle: 'SRG-OS-000276-GPOS-00106'
  tag fix_id: 'F-62095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
