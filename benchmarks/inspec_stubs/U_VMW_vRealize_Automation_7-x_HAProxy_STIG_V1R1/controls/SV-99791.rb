control 'SV-99791' do
  title 'HAProxy log files must not be accessible to unauthorized users.'
  desc 'The HAProxy log files provide audit data useful to the discovery of suspicious behavior. The log files may contain usernames and passwords in clear text as well as other information that could aid a malicious user with unauthorized access attempts to the database. Generation and protection of these files helps support security monitoring efforts.'
  desc 'check', 'At the command prompt, execute the following command:

ls -la /var/log/vmware/vcac/vcac-config.log

If the log file has permissions more permissive than "640", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

sed -i "/^[^#]*UMASK/ c\\UMASK 077" /etc/login.defs'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89141'
  tag rid: 'SV-99791r1_rule'
  tag stig_id: 'VRAU-HA-000095'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-95883r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
