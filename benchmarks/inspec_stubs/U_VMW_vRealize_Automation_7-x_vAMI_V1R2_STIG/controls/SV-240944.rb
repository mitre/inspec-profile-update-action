control 'SV-240944' do
  title 'The vAMI must use _sfcBasicAuthenticate for initial authentication of the remote administrator.'
  desc 'Unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of session identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions. Application servers must generate a unique session identifier for each application session to prevent session hijacking.'
  desc 'check', 'At the command prompt, execute the following command:

grep basicAuthEntry /opt/vmware/etc/sfcb/sfcb.cfg

If the value of "basicAuthEntry" is missing, commented out, or not "_sfcBasicAuthenticate", this is a finding.'
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'basicAuthEntry: _sfcBasicAuthenticate'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44177r675997_chk'
  tag severity: 'medium'
  tag gid: 'V-240944'
  tag rid: 'SV-240944r879638_rule'
  tag stig_id: 'VRAU-VA-000295'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag fix_id: 'F-44136r675998_fix'
  tag 'documentable'
  tag legacy: ['SV-100881', 'V-90231']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
