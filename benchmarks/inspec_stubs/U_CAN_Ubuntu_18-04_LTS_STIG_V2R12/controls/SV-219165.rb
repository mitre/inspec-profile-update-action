control 'SV-219165' do
  title 'The Ubuntu operating system must display the date and time of the last successful account logon upon logon.'
  desc 'Configuring the Ubuntu operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify users are provided with feedback on when account accesses last occurred.

Check that "pam_lastlog" is used and not silent with the following command:

# grep pam_lastlog /etc/pam.d/login

session required pam_lastlog.so showfailed

If "pam_lastlog" is missing from "/etc/pam.d/login" file, is not "required", or the "silent" option is present, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/postlogin-ac". 

Add the following line to the top of "/etc/pam.d/login":

session required pam_lastlog.so showfailed'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20890r304823_chk'
  tag severity: 'low'
  tag gid: 'V-219165'
  tag rid: 'SV-219165r858512_rule'
  tag stig_id: 'UBTU-18-010032'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20889r304824_fix'
  tag 'documentable'
  tag legacy: ['SV-109661', 'V-100557']
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
