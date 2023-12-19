control 'SV-13603' do
  title 'DNS logs are not reviewed daily or a real-time log analysis or network management tool is not employed to immediately alert an administrator of critical DNS system messages.'
  desc 'If a responsible administrator does not review DNS logs daily, then there is the potential that an attack or other security issue can go unnoticed for a day or more, which is unacceptable in DOD environments.'
  desc 'check', "If reviewing of logs is anything less than daily, or isn't performed by the ISSO/ISSM or under the ISSO/ISSM oversight, then this is a finding.

In many cases, DNS logs are included within the system logs. If this is the case, then daily review of the system logs meets the requirement.
 
If the site employs special software to scan logs for special events or key words, then this is also acceptable so long as the system issues real time alerts or is monitored at least daily.

Windows

DNS log files are normally kept in two locations. The system event logs which can be viewed from Event Viewer found under the Administrative tools from the Start Menu. In addition, debug logging options such as query, notify, and update requirements can be viewed in a file named %systemroot%\\system32\\dns\\dns.log.

BIND

BIND logging files can be found by viewing the /etc/named.conf file. Within the named.conf will be an option for logging that will display the file path to the log files. In addition, most Unix machines will also log information in the syslog on the system.

Windows

DNS log files are normally kept in two locations.  The system event logs which can be viewed from Event Viewer found under the Administrative tools from the Start Menu.  In addition, debug logging options such as query, notify, and update requirements can be viewed in a file named %systemroot%\\system32\\dns\\dns.log.

BIND

BIND logging files can be found by viewing the /etc/named.conf file.  Within the named.conf will be an option for logging that will display the file path to the log files.  In addition, most Unix machines will also log information in the syslog on the system."
  desc 'fix', 'The ISSO/ISSM should commit to reviewing logs daily or have oversight of the review daily, perhaps establishing a rotation for this purpose to ensure that days are not missed. Having a primary administrator and backup administrators rotate this responsibility will prevent a problem or warning sign from being missed because of an error in judgment.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3356r3_chk'
  tag severity: 'medium'
  tag gid: 'V-13035'
  tag rid: 'SV-13603r2_rule'
  tag stig_id: 'DNS0115'
  tag gtitle: 'DNS logs are not reviewed daily.'
  tag fix_id: 'F-4339r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
