control 'SV-224087' do
  title 'IBM z/OS UNIX BPXPRMxx security parameters in PARMLIB must be properly specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
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
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25760r516660_chk'
  tag severity: 'medium'
  tag gid: 'V-224087'
  tag rid: 'SV-224087r561402_rule'
  tag stig_id: 'TSS0-US-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25748r516661_fix'
  tag 'documentable'
  tag legacy: ['V-98881', 'SV-107985']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
