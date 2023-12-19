control 'SV-223819' do
  title 'IBM z/OS using DFSMS must properly specify SYS(x).PARMLIB(IGDSMSxx), SMS parameter settings.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Review the logical parmlib data sets, example: SYS1.PARMLIB(IGDSMSxx), for the following SMS parameter settings:

Parameter Key
SMS
ACDS(ACDS data set name)
COMMDS(COMMDS data set name)

If the required parameters are defined, this is not a finding.'
  desc 'fix', 'Configure the DFSMS-related PDS members and statements specified in the system parmlib concatenation as outlined below:

Parameter Key
SMS
ACDS(ACDS data set name)
COMMDS(COMMDS data set name)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25492r515145_chk'
  tag severity: 'medium'
  tag gid: 'V-223819'
  tag rid: 'SV-223819r604139_rule'
  tag stig_id: 'RACF-SM-000050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25480r515146_fix'
  tag 'documentable'
  tag legacy: ['SV-107449', 'V-98345']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
