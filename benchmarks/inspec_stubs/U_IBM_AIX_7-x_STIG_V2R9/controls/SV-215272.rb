control 'SV-215272' do
  title 'AIX time synchronization configuration file must be owned by root.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised. If the configuration files controlling time synchronization are not owned by a system account, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the ownership of /etc/ntp.conf using command:
# ls -al  /etc/ntp.conf

The above command should yield the following output:
-rw-r-----    1 root     system          993 Aug 25 18:26 /etc/ntp.conf

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the file to root using command: 
# chown root /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16470r294267_chk'
  tag severity: 'medium'
  tag gid: 'V-215272'
  tag rid: 'SV-215272r508663_rule'
  tag stig_id: 'AIX7-00-002081'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16468r294268_fix'
  tag 'documentable'
  tag legacy: ['V-91601', 'SV-101699']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
