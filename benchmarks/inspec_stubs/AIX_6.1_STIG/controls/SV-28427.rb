control 'SV-28427' do
  title 'The system must not have the UUCP service active.'
  desc 'The UUCP utility is designed to assist in transferring files, executing remote commands, and sending e-mail between UNIX systems over phone lines and direct connections between systems. The UUCP utility is a primitive and arcane system with many security issues. There are alternate data transfer utilities/products that can be configured to more securely transfer data by providing for authentication as well as encryption.'
  desc 'check', '# grep uucp /etc/inetd.conf
If uucp is found enabled, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the uucp service.  Restart the inetd service.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28692r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4696'
  tag rid: 'SV-28427r1_rule'
  tag stig_id: 'GEN005280'
  tag gtitle: 'GEN005280'
  tag fix_id: 'F-25720r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
