control 'SV-239599' do
  title 'The SLES for vRealize must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Check "/etc/audit/auditd.conf" file for the "space_left_action" parameter with the following command:

# cat /etc/audit/auditd.conf | grep space_left_action 

If the "space_left_action" parameter is missing, set to "ignore", set to "suspend", set to "single", set to "halt", or is blank, this is a finding

Expected Result: 

space_left_action = SYSLOG

Notes: 
If the "space_left_action" parameter is set to "exec" the system executes a designated script. 

If this script informs the SA of the event, this is not a finding.

If the "space_left_action" parameter is set to "email" and the "action_mail_acct" parameter is not set to the email address of the system administrator, this is a finding. 

The "action_mail_acct" parameter, if missing, defaults to "root". Note that if the email address of the system administrator is on a remote system "sendmail" must be available.'
  desc 'fix', 'Set the "space_left_action" parameter to the valid setting "SYSLOG", by running the following command:

# sed -i "/^[^#]*space_left_action/ c\\admin_space_left_action = SYSLOG" /etc/audit/auditd.conf

Restart the audit service: 

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42832r662246_chk'
  tag severity: 'medium'
  tag gid: 'V-239599'
  tag rid: 'SV-239599r662248_rule'
  tag stig_id: 'VROM-SL-001045'
  tag gtitle: 'SRG-OS-000344-GPOS-00135'
  tag fix_id: 'F-42791r662247_fix'
  tag 'documentable'
  tag legacy: ['SV-99319', 'V-88669']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
