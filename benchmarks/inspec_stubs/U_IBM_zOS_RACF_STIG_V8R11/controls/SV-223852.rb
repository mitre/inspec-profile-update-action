control 'SV-223852' do
  title 'IBM z/OS UNIX BPXPRMxx security parameters in PARMLIB must be properly specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Refer to the BPXPRM00 member of SYS1.PARMLIB.

If the required parameter keywords and values are defined as detailed below, this is not a finding.

Parameter Keyword Value
SUPERUSER BPXROOT
TTYGROUP TTY
STEPLIBLIST /etc/steplib
USERIDALIASTABLE Will not be specified.
ROOT SETUID will be specified
MOUNT NOSETUID
SETUID (for Vendor-provided files)SECURITY
STARTUP_PROC OMVS'
  desc 'fix', 'Define the settings in PARMLIB member BPXPRMxx for z/OS UNIX security parameters values to conform to the specifications below:
Parameter Keyword Value
SUPERUSER BPXROOT
TTYGROUP TTY
STEPLIBLIST /etc/steplib
USERIDALIASTABLE Will not be specified.
ROOT SETUID will be specified
MOUNT NOSETUIDSETUID (for Vendor-provided files)SECURITY
STARTUP_PROC OMVS'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25525r515244_chk'
  tag severity: 'medium'
  tag gid: 'V-223852'
  tag rid: 'SV-223852r604139_rule'
  tag stig_id: 'RACF-US-000150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25513r515245_fix'
  tag 'documentable'
  tag legacy: ['SV-107515', 'V-98411']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
