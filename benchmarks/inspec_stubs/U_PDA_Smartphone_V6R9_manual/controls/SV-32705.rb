control 'SV-32705' do
  title 'The device minimum password/passcode length must be set as required.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space.'
  desc 'check', 'Review the mobile operating system configuration to determine if the device enforces a minimum length for the device unlock password. For device unlock on mobile operating systems with no access to sensitive or classified information, the requirement is a minimum of 4 numbers. For access mobile devices with sensitive information, the minimum length is 6. If the mobile device places sensitive information or security functions in “security container” applications only, then a compliant configuration is to require a 6-character or longer password to enter the container application, and a 4-digit or longer password to unlock the device. If the device does not enforce a minimum length for the device unlock password or, where applicable, the security container, this is a finding.'
  desc 'fix', 'Configure the mobile operating system to enforce a minimum length for the device unlock password.  Where a security container application is used in lieu of mobile operating system protections, configure the security container application to enforce a minimum length password for entry into the application.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-32926r5_chk'
  tag severity: 'medium'
  tag gid: 'V-25016'
  tag rid: 'SV-32705r2_rule'
  tag stig_id: 'WIR-MOS-PDA-011'
  tag gtitle: 'Minimum password/passcode length'
  tag fix_id: 'F-27687r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWN-1, IAIA-1'
end
