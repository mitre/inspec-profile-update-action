control 'SV-99029' do
  title 'The SLES for vRealize must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Check /etc/audit/auditd.conf for the "space_left_action" with the following command:

# cat /etc/audit/auditd.conf | grep space_left_action 

If the "space_left_action" parameter is missing, set to "ignore", set to "suspend", set to "single", set to "halt", or is blank, this is a finding.

Expected Result:
space_left_action = SYSLOG

Notes: 
If the space_left_action is set to "exec" the system executes a designated script. If this script informs the SA of the event, this is not a finding.

If the space_left_action is set to "email" and the "action_mail_acct" parameter is not set to the email address of the system administrator, this is a finding. 

The "action_mail_acct" parameter, if missing, defaults to "root".

Note:  If the email address of the system administrator is on a remote system "sendmail" must be available.'
  desc 'fix', 'Set the "space_left_action" parameter to the valid setting "SYSLOG", by running the following command:

# sed -i "/^[^#]*space_left_action/ c\\space_left_action = SYSLOG" /etc/audit/auditd.conf

Restart the audit service: 

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88379'
  tag rid: 'SV-99029r1_rule'
  tag stig_id: 'VROM-SL-000125'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-95121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
