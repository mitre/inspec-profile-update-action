control 'SV-223556' do
  title 'IBM z/OS PASSWORD data set and OS passwords must not be used.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Ask the system administrator to determine if the system PASSWORD data set and OS passwords are being used.

If, based on the information provided, it can be determined that the system PASSWORD data set and OS passwords are not used, this is not a finding.

If it is evident that OS passwords are utilized, this is a finding.'
  desc 'fix', 'System programmers will ensure that the old OS Password Protection is not used and any data protected by the old OS Password technology is removed and protection is replaced by the ACP.

Review the contents of the PASSWORD data set. Ensure that any protections it provides are provided by the ACP and delete the PASSWORD data set.

Access to data sets on z/OS systems can be protected using the OS password capability of MVS. This capability has been available in MVS for many years, and its use is commonly found in data centers. Since the advent of ACPs, the use of OS passwords for file protection has diminished, and is commonly considered archaic and of little use. The use of z/OS passwords is not supported by all the ACPs.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25229r504695_chk'
  tag severity: 'medium'
  tag gid: 'V-223556'
  tag rid: 'SV-223556r533198_rule'
  tag stig_id: 'ACF2-OS-000200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25217r504696_fix'
  tag 'documentable'
  tag legacy: ['SV-106921', 'V-97817']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
