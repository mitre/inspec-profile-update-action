control 'SV-234957' do
  title 'The Information System Security Officer (ISSO) and System Administrator (SA), at a minimum, must have mail aliases to be notified of a SUSE operating system audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify the administrators are notified in the event of a SUSE operating system audit processing failure by checking that "/etc/aliases" has a defined value for root.

> grep -i "^postmaster:" /etc/aliases

postmaster: root

If the above command does not return a value of "root", or the output is commented out, this is a finding

Verify the alias for root forwards to a monitored e-mail account:

> grep -i "^root:" /etc/aliases
root: person@server.mil

If the alias for root does not forward to a monitored e-mail account, or the output is commented out, this is a finding.'
  desc 'fix', %q(Configure the auditd service to notify the administrators in the event of a SUSE operating system audit processing failure. 

Configure an alias value for the postmaster with the following command:

> sudo sh -c 'echo "postmaster: root" >> /etc/aliases' 

Configure an alias for root that forwards to a monitored email address with the following command:

> sudo sh -c 'echo "root: box@server.mil" >> /etc/aliases'

The following command must be run to implement changes to the /etc/aliases file:

> sudo newaliases)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38145r619140_chk'
  tag severity: 'medium'
  tag gid: 'V-234957'
  tag rid: 'SV-234957r622137_rule'
  tag stig_id: 'SLES-15-030580'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-38108r619141_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
