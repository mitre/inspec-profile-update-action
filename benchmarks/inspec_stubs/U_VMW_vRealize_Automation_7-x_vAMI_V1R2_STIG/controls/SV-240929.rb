control 'SV-240929' do
  title 'The vAMI must have sfcb logging enabled.'
  desc 'Privileged commands are commands that change the configuration or data of the application server. Since this type of command changes the application server configuration and could possibly change the security posture of the application server, these commands need to be logged to show the full-text of the command executed. Without the full-text, reconstruction of harmful events or forensic analysis is not possible. Organizations can consider limiting the additional log information to only that information explicitly needed for specific log requirements. At a minimum, the organization must log either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain log trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'At the command prompt, execute the following command:

grep traceLevel /opt/vmware/etc/sfcb/sfcb.cfg

If the value of "traceLevel" is not set to "1", or is missing or is commented out, this is a finding.'
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'traceLevel: 1'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44162r675952_chk'
  tag severity: 'medium'
  tag gid: 'V-240929'
  tag rid: 'SV-240929r879569_rule'
  tag stig_id: 'VRAU-VA-000105'
  tag gtitle: 'SRG-APP-000101-AS-000072'
  tag fix_id: 'F-44121r675953_fix'
  tag 'documentable'
  tag legacy: ['SV-100851', 'V-90201']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
