control 'SV-38301' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must not have an extended ACL.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Verify the NTP configuration file has no extended ACL.
# ls -lL /etc/ntp.conf
If the permissions include a "+" the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22297'
  tag rid: 'SV-38301r1_rule'
  tag stig_id: 'GEN000253'
  tag gtitle: 'GEN000253'
  tag fix_id: 'F-31500r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
