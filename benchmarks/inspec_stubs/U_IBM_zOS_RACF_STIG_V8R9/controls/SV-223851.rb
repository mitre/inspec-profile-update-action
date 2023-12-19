control 'SV-223851' do
  title 'IBM z/OS UNIX OMVS parameters in PARMLIB must be properly specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', "Refer to the IEASYS00 member of SYS1.PARMLIB.

If the parameter is specified as OMVS=xx or OMVS=(xx,xx,...) in the IEASYSxx member, this is not a finding.

If the OMVS statement is not specified, OMVS=DEFAULT is used. In minimum mode there is no access to permanent file systems or to the shell, and IBM's Communication Server TCP/IP will not run."
  desc 'fix', "Configure the settings in PARMLIB and /etc for z/OS UNIX security parameters with values that conform to the specifications below:

The parameter is specified as OMVS=xx or OMVS=(xx,xx,...) in the IEASYSxx member.

Note: If the OMVS statement is not specified, OMVS=DEFAULT is used. In minimum mode there is no access to permanent file systems or to the shell, and IBM's Communication Server TCP/IP will not run."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25524r868899_chk'
  tag severity: 'medium'
  tag gid: 'V-223851'
  tag rid: 'SV-223851r868901_rule'
  tag stig_id: 'RACF-US-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25512r868900_fix'
  tag 'documentable'
  tag legacy: ['SV-107513', 'V-98409']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
