control 'SV-223617' do
  title 'IBM z/OS UNIX security parameters in etc/profile must be properly specified.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF COMMAND SHELL enter:
ISHELL
/etc/profile

If the final or only instance of the UMASK command in /etc/profile is specified as "umask 077", this is not a finding.

If the LOGNAME variable is marked read-only (i.e., "readonly LOGNAME") in /etc/profile, this is not a finding.'
  desc 'fix', 'Configure the etc/profile to specify the UMASK command is executed with a value of 077 and the LOGNAME variable is marked read-only for the /etc/profile file, exceptions are documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25290r858894_chk'
  tag severity: 'medium'
  tag gid: 'V-223617'
  tag rid: 'SV-223617r861185_rule'
  tag stig_id: 'ACF2-US-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25278r500987_fix'
  tag 'documentable'
  tag legacy: ['SV-107043', 'V-97939']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
