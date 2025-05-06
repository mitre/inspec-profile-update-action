control 'SV-37418' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must not have an extended ACL.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', "Check the NTP configuration file has no extended ACL.
# ls -l /etc/ntp.conf
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the NTP configuration file.
# setfacl --remove-all /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36101r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22297'
  tag rid: 'SV-37418r1_rule'
  tag stig_id: 'GEN000253'
  tag gtitle: 'GEN000253'
  tag fix_id: 'F-23451r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
