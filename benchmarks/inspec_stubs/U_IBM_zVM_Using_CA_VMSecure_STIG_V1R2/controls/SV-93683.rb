control 'SV-93683' do
  title 'The IBM z/VM system administrator must develop routines and processes for the proper configuration and maintenance of Software.'
  desc 'Proper configuration management procedures for information systems provide for the proper configuration and maintenance in accordance with local policies restrictions and/or rules. Failure to properly configure and maintain system software and applications on the information system could result in a weakened security posture.'
  desc 'check', 'Ask the system administrator (SA) for documented procedures and routines for proper configuration management of software.

If there are no procedures or the procedures are not documented and on file with the ISSO, this is a finding.'
  desc 'fix', 'Develop a procedure for proper configuration of software components.

Include proper maintenance procedures.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78565r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78977'
  tag rid: 'SV-93683r1_rule'
  tag stig_id: 'IBMZ-VM-002350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85727r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
