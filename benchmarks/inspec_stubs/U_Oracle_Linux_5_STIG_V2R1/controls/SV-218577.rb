control 'SV-218577' do
  title 'The system must not have the UUCP service active.'
  desc 'The UUCP utility is designed to assist in transferring files, executing remote commands, and sending e-mail between UNIX systems over phone lines and direct connections between systems. The UUCP utility is a primitive and arcane system with many security issues. There are alternate data transfer utilities/products that can be configured to more securely transfer data by providing for authentication as well as encryption.'
  desc 'check', '# service uucp status
if UUCP is "running", this is a finding.'
  desc 'fix', '# chkconfig uucp off
# service uucp stop
# service xinetd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20052r562807_chk'
  tag severity: 'medium'
  tag gid: 'V-218577'
  tag rid: 'SV-218577r603259_rule'
  tag stig_id: 'GEN005280'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20050r562808_fix'
  tag 'documentable'
  tag legacy: ['V-4696', 'SV-63353']
  tag cci: ['CCI-001436', 'CCI-000381']
  tag nist: ['AC-17 (8)', 'CM-7 a']
end
