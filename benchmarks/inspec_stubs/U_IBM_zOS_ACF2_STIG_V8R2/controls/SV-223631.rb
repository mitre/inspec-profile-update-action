control 'SV-223631' do
  title 'IBM z/OS UNIX BPXPRMxx security parameters in PARMLIB must be properly specified.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Refer to the proper BPXPRMxx member in SYS1.PARMLIB.

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
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25304r504851_chk'
  tag severity: 'medium'
  tag gid: 'V-223631'
  tag rid: 'SV-223631r533198_rule'
  tag stig_id: 'ACF2-US-000160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25292r504852_fix'
  tag 'documentable'
  tag legacy: ['V-97967', 'SV-107071']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
