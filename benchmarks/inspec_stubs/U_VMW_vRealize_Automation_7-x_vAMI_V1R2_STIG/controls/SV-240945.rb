control 'SV-240945' do
  title 'The vAMI must have the correct authentication set for HTTPS connections.'
  desc 'This requirement focuses on communications protection at the application session, versus network packet level. The intent of this control is to establish grounds for confidence at each end of a communications session in the ongoing identity of the other party and in the validity of the information being transmitted. Unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of said identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.'
  desc 'check', 'At the command prompt, execute the following command:

grep doBasicAuth /opt/vmware/etc/sfcb/sfcb.cfg

If the value of "doBasicAuth" is missing, commented out, or not "true", this is a finding.'
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'doBasicAuth: true'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44178r676000_chk'
  tag severity: 'medium'
  tag gid: 'V-240945'
  tag rid: 'SV-240945r879638_rule'
  tag stig_id: 'VRAU-VA-000300'
  tag gtitle: 'SRG-APP-000223-AS-000151'
  tag fix_id: 'F-44137r676001_fix'
  tag 'documentable'
  tag legacy: ['SV-100883', 'V-90233']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
