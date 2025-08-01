control 'SV-37688' do
  title 'The system must not have the UUCP service active.'
  desc 'The UUCP utility is designed to assist in transferring files, executing remote commands, and sending e-mail between UNIX systems over phone lines and direct connections between systems. The UUCP utility is a primitive and arcane system with many security issues. There are alternate data transfer utilities/products that can be configured to more securely transfer data by providing for authentication as well as encryption.'
  desc 'check', '# service uucp status
if UUCP is "running", this is a finding.'
  desc 'fix', '# chkconfig uucp off
# service uucp stop
# service xinetd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4696'
  tag rid: 'SV-37688r1_rule'
  tag stig_id: 'GEN005280'
  tag gtitle: 'GEN005280'
  tag fix_id: 'F-31895r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
