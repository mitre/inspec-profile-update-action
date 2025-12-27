control 'SV-248724' do
  title 'The OL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted of an audit processing failure event.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 
 
Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 
 
This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify that the SA and ISSO (at a minimum) are notified in the event of an audit processing failure with the following command: 
 
$ sudo grep action_mail_acct /etc/audit/auditd.conf 
 
action_mail_acct = root 
 
If the value of the "action_mail_acct" keyword is not set to "root" and/or other accounts for security personnel, the "action_mail_acct" keyword is missing, or the retuned line is commented out, ask the SA to indicate how they and the ISSO are notified of an audit process failure.  
 
If there is no evidence of the proper personnel being notified of an audit processing failure, this is a finding.'
  desc 'fix', 'Configure the "auditd" service to notify the SA and ISSO in the event of an audit processing failure.  
 
Edit the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations: 
 
action_mail_acct = root'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52158r779736_chk'
  tag severity: 'medium'
  tag gid: 'V-248724'
  tag rid: 'SV-248724r779738_rule'
  tag stig_id: 'OL08-00-030020'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-52112r779737_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
