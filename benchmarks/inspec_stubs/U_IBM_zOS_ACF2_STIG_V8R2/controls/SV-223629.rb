control 'SV-223629' do
  title 'IBM z/OS UNIX OMVS parameters in PARMLIB must be properly specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'Refer to the IEASYS00 member of SYS1.PARMLIB.

If the parameter is specified as OMVS=xx or OMVS=(xx,xx,…) in the IEASYSxx member, this is not a finding.

If the OMVS statement is not specified, OMVS=DEFAULT is used. In minimum mode there is no access to permanent file systems or to the shell, and IBM’s Communication Server TCP/IP will not run.'
  desc 'fix', "Configure the settings in PARMLIB and /etc for z/OS UNIX security parameters with values that conform to the specifications below:

The parameter is specified as OMVS=xx or OMVS=(xx,xx,…) in the IEASYSxx member.

Note: If the OMVS statement is not specified, OMVS=DEFAULT is used. In minimum mode there is no access to permanent file systems or to the shell, and IBM's Communication Server TCP/IP will not run."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25302r504845_chk'
  tag severity: 'medium'
  tag gid: 'V-223629'
  tag rid: 'SV-223629r533198_rule'
  tag stig_id: 'ACF2-US-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25290r504846_fix'
  tag 'documentable'
  tag legacy: ['SV-107067', 'V-97963']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
