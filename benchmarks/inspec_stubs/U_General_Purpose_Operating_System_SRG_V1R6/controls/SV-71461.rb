control 'SV-71461' do
  title 'The operating system must notify system administrators and ISSOs when accounts are removed.'
  desc 'When operating system accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. Sending notification of account removal events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system notifies System Administrators and Information System Security Officers for account removal actions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to notify System Administrators and Information System Security Officers for account removal actions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57201'
  tag rid: 'SV-71461r2_rule'
  tag stig_id: 'SRG-OS-000277-GPOS-00107'
  tag gtitle: 'SRG-OS-000277-GPOS-00107'
  tag fix_id: 'F-62097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
