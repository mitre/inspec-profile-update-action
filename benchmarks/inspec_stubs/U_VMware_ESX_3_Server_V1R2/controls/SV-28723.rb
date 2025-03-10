control 'SV-28723' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must not have an extended ACL.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', "Check for an extended ACL on the NTP configuration file.
# ls -l ntp.conf
If the permissions contain a '+' the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the extended ACL from the ntp.conf file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29018r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22297'
  tag rid: 'SV-28723r1_rule'
  tag stig_id: 'GEN000253'
  tag gtitle: 'GEN000253'
  tag fix_id: 'F-26028r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
