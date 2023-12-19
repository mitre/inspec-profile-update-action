control 'SV-216273' do
  title 'The operating system must alert designated organizational officials in the event of an audit processing failure.'
  desc 'Proper alerts to system administrators and IA officials of audit failures ensure a timely response to critical system issues.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

The root role is required.

Verify the presence of an audit_warn entry in /etc/mail/aliases.
# /usr/lib/sendmail -bv audit_warn
If the response is:
audit_warn... User unknown

this is a finding.

Review the output of the command and verify that the audit_warn alias notifies the appropriate users in this form:

audit_warn:user1,user2

If an appropriate user is not listed, this is a finding.'
  desc 'fix', 'The root role is required. 

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Add an audit_warn alias to /etc/mail/aliases that will forward to designated system administrator(s).

# pfedit /etc/mail/aliases

Insert a line in the form:
audit_warn:user1,user2

Put the updated aliases file into service.
# newaliases'
  impact 0.7
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17509r370907_chk'
  tag severity: 'high'
  tag gid: 'V-216273'
  tag rid: 'SV-216273r603267_rule'
  tag stig_id: 'SOL-11.1-010390'
  tag gtitle: 'SRG-OS-000046'
  tag fix_id: 'F-17507r370908_fix'
  tag 'documentable'
  tag legacy: ['V-47845', 'SV-60719']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
