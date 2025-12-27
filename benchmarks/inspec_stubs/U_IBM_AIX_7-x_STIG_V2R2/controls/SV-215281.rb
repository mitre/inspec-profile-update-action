control 'SV-215281' do
  title 'AIX time synchronization configuration file must have mode 0640 or less permissive.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised. File permissions more permissive than 0640 for time synchronization configuration file may allow     access and change the config file by system intruders or malicious users, could result in the failure of time synchronization.'
  desc 'check', 'Determine the mode of the ntp.conf file: 
# ls -l /etc/ntp.conf 

The above command should yield the following output:
-rw-r-----    1 root     system          993 Aug 25 18:26 /etc/ntp.conf

If the mode is more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the mode of the "ntp.conf" file to "0640" or less permissive: 
# chmod 0640 /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16479r294294_chk'
  tag severity: 'medium'
  tag gid: 'V-215281'
  tag rid: 'SV-215281r508663_rule'
  tag stig_id: 'AIX7-00-002090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16477r294295_fix'
  tag 'documentable'
  tag legacy: ['V-91605', 'SV-101703']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
