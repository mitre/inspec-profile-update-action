control 'SV-221765' do
  title 'The Oracle Linux operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

'
  desc 'check', 'Confirm the audit configuration regarding how auditing processing failures are handled.

Check to see what level "auditctl" is set to with following command: 

     # auditctl -s | grep -i "fail"

     failure 2

Note: If the value of "failure" is set to "2", the system is configured to panic (shut down) in the event of an auditing failure. If the value of "failure" is set to "1", the system will not shut down and instead will record the audit failure in the kernel log. If the system is configured per requirement OL07-00-031000, the kernel log will be sent to a log aggregation server and generate an alert.

If the "failure" setting is set to any value other than "1" or "2", this is a finding.

If the "failure" setting is not set, this must be upgraded to a CAT I finding.

If the "failure" setting is set to "1" but the availability concern is not documented or there is no monitoring of the kernel log, this must be downgraded to a CAT III finding.'
  desc 'fix', 'Configure the operating system to shut down in the event of an audit processing failure.

Add or correct the option to shut down the operating system with the following command:

     # auditctl -f 2

Edit the "/etc/audit/rules.d/audit.rules" file and add the following line:

     -f 2

If availability has been determined to be more important, and this decision is documented with the ISSO, configure the operating system to notify system administration staff and ISSO staff in the event of an audit processing failure with the following command:

     # auditctl -f 1

Edit the "/etc/audit/rules.d/audit.rules" file and add the following line:

     -f 1

Kernel log monitoring must also be configured to properly alert designated staff.

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36287r880592_chk'
  tag severity: 'medium'
  tag gid: 'V-221765'
  tag rid: 'SV-221765r880594_rule'
  tag stig_id: 'OL07-00-030010'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-36251r880593_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000047-GPOS-00023']
  tag 'documentable'
  tag legacy: ['SV-108373', 'V-99269']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
