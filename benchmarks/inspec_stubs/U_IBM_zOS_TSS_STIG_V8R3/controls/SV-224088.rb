control 'SV-224088' do
  title 'IBM z/OS UNIX security parameters in etc/profile must be properly specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ISPF Command Shell enter:
ISHELL
/etc/profile
If the final or only instance of the UMASK command in /etc/profile is specified as "umask 077", this is not a finding.

If the LOGNAME variable is marked read-only (i.e., "readonly LOGNAME") in /etc/profile, this is not a finding.'
  desc 'fix', 'Configure the etc/profile to specify the UMASK command is executed with a value of 077 and the LOGNAME variable is marked read-only for the /etc/profile file, exceptions are documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25761r516663_chk'
  tag severity: 'medium'
  tag gid: 'V-224088'
  tag rid: 'SV-224088r561402_rule'
  tag stig_id: 'TSS0-US-000150'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25749r516664_fix'
  tag 'documentable'
  tag legacy: ['V-98883', 'SV-107987']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
