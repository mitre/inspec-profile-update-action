control 'SV-37506' do
  title 'The system must not use .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops which could degrade system performance.'
  desc 'fix', "Disable forwarding for sendmail and remove .forward files from the system

Procedure:
Edit the /etc/mail/sendmail.mc file to change the ForwardPath entry to a null path by adding the line
define(`confFORWARD_PATH',`')
rebuild the sendmail.cf file.
If the /etc/mail/sendmail.mc file does not exist, the sendmail.cf file should be updated directly.

Remove all .forward files on the system
# find / -name .forward -delete"
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4385'
  tag rid: 'SV-37506r3_rule'
  tag stig_id: 'GEN004580'
  tag gtitle: 'GEN004580'
  tag fix_id: 'F-31416r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
