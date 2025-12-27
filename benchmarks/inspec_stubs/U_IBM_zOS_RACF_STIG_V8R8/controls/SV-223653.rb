control 'SV-223653' do
  title 'IBM RACF SETROPTS LOGOPTIONS must be properly configured.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. 

'
  desc 'check', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

Verify that the following LOGOPTIONS are specified:
LOGOPTIONS "FAILURES" CLASSES = <all the classes listed in the “ACTIVE” class as a minimum>
LOGOPTIONS "NEVER" CLASSES = NONE

The other LOGOPTIONS may be site determined.

If the LOGOPTIONS are not set as described above, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

Ensure that the following LOGOPTIONS are specified:
LOGOPTIONS "FAILURES" CLASSES = <all the classes listed in the “ACTIVE” class as a minimum>
LOGOPTIONS "NEVER" CLASSES = NONE

The other LOGOPTIONS may be site determined.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25326r514648_chk'
  tag severity: 'medium'
  tag gid: 'V-223653'
  tag rid: 'SV-223653r853569_rule'
  tag stig_id: 'RACF-ES-000050'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-25314r514649_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['SV-107115', 'V-98011']
  tag cci: ['CCI-000018', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000172', 'CCI-001404', 'CCI-001405', 'CCI-002884']
  tag nist: ['AC-2 (4)', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'MA-4 (1) (a)']
end
