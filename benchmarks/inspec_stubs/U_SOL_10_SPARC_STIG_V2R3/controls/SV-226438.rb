control 'SV-226438' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be owned by root.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system account, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Run ls -l /etc/inet/ntp.conf to display the owner of the NTP configuration file.  If the owner is not root, this is a finding.'
  desc 'fix', 'Change the owner of the NTP configuration file to root.
# chown root /etc/inet/ntp.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28599r482678_chk'
  tag severity: 'medium'
  tag gid: 'V-226438'
  tag rid: 'SV-226438r603265_rule'
  tag stig_id: 'GEN000250'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28587r482679_fix'
  tag 'documentable'
  tag legacy: ['V-22294', 'SV-26293']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
