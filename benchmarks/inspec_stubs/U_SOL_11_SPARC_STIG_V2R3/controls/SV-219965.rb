control 'SV-219965' do
  title 'The audit system must alert the SA when the audit storage volume approaches its capacity.'
  desc 'Filling the audit storage area can result in a denial of service or system outage and can lead to events going undetected.'
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
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21675r370901_chk'
  tag severity: 'medium'
  tag gid: 'V-219965'
  tag rid: 'SV-219965r603267_rule'
  tag stig_id: 'SOL-11.1-010370'
  tag gtitle: 'SRG-OS-000343'
  tag fix_id: 'F-21674r370902_fix'
  tag 'documentable'
  tag legacy: ['SV-60709', 'V-47835']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
