control 'SV-218200' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must not have an extended ACL.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', "Check the NTP configuration file has no extended ACL.
# ls -l /etc/ntp.conf
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the NTP configuration file.
# setfacl --remove-all /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19675r568537_chk'
  tag severity: 'medium'
  tag gid: 'V-218200'
  tag rid: 'SV-218200r603259_rule'
  tag stig_id: 'GEN000253'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19673r568538_fix'
  tag 'documentable'
  tag legacy: ['V-22297', 'SV-63177']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
