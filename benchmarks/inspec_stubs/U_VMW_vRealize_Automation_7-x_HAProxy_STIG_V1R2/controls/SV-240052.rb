control 'SV-240052' do
  title 'HAProxy log files must not be accessible to unauthorized users.'
  desc 'The HAProxy log files provide audit data useful to the discovery of suspicious behavior. The log files may contain usernames and passwords in clear text as well as other information that could aid a malicious user with unauthorized access attempts to the database. Generation and protection of these files helps support security monitoring efforts.'
  desc 'check', 'At the command prompt, execute the following command:

ls -la /var/log/vmware/vcac/vcac-config.log

If the log file has permissions more permissive than "640", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

sed -i "/^[^#]*UMASK/ c\\UMASK 077" /etc/login.defs'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43285r665323_chk'
  tag severity: 'medium'
  tag gid: 'V-240052'
  tag rid: 'SV-240052r879576_rule'
  tag stig_id: 'VRAU-HA-000095'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-43244r665324_fix'
  tag 'documentable'
  tag legacy: ['SV-99791', 'V-89141']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
