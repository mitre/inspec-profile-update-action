control 'SV-99793' do
  title 'HAProxy log files must be protected from unauthorized modification.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.'
  desc 'check', 'At the command prompt, execute the following command:

ls -la /var/log/vmware/vcac/vcac-config.log

If the log file has permissions more permissive than "640", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

sed -i "/^[^#]*UMASK/ c\\UMASK 077" /etc/login.defs'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89143'
  tag rid: 'SV-99793r1_rule'
  tag stig_id: 'VRAU-HA-000100'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag fix_id: 'F-95885r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
