control 'SV-223739' do
  title 'IBM z/OS FTP.DATA configuration statements for the FTP Server must be specified in accordance with requirements.'
  desc 'This requirement is intended to cover both traditional interactive logons to information systems and general accesses to information systems that occur in other types of architectural configurations (e.g., service-oriented architectures).'
  desc 'check', 'Refer to the Data configuration file specified on the SYSFTPD DD statement in the FTP started task JCL.

If the UMASK statement is coded with a value of 077, this is not a finding.'
  desc 'fix', 'Configure the FTP configuration to include the UMASK statement with a value of 077. 

If the FTP Server requires a UMASK value less restrictive than 077, requirements should be justified and documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25412r514905_chk'
  tag severity: 'medium'
  tag gid: 'V-223739'
  tag rid: 'SV-223739r604139_rule'
  tag stig_id: 'RACF-FT-000070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25400r514906_fix'
  tag 'documentable'
  tag legacy: ['V-98185', 'SV-107289']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
