control 'SV-77559' do
  title 'A notification mechanism or process must be in place to notify Administrators of out of date DAT, detected malware and error codes.'
  desc 'Failure of anti-virus signature updates will eventually render the software to be useless in protecting the Linux system from malware. Administration notification for failed updates, via SMTP, will ensure timely remediation of errors causing DATs to not be updated.'
  desc 'check', 'The preferred method for notification is via ePO Automatic Responses using SMTP. 

Consult with the System Administrator to determine whether ePO Automatic Responses are configured or whether some other notification mechanism (i.e., regular manual review of reports)is used.

If ePO Automatic Responses are not configured, some other notification mechanism must be configured. 

For ePO Automatic Response using SMTP:

Log onto the ePO server console.

From Menu, select Automation >> Automatic Responses.

With the assistance of the System Administrator, determine the Automatic Responses configured for this requirement.

Click on Edit to review each of the designated Automatic Responses.

Automatic Responses must be configured for the following Event Descriptions, at a minimum, with a response of "Send Email" to System Administrator(s).

The DAT version was not new enough.
Boot record infection clean error.
Buffer overflow detected and NOT blocked.
Centralized Alerting-Scan reported an internal application error.
Centralized Alerting-Scan reports general system error.
Centralized Alerting-Scan reports memory allocation error.
File infected. Delete failed, quarantine failed.

If Automatic Response is not configured to detect the minimum Event Descriptions and/or is not configured to send an email notification to the System Administrator(s) or some other mechanism is not used to provide this notification to System Administrators, this is a finding.'
  desc 'fix', 'Configure Automatic Response to capture all required event descriptions and to send email notifications to the System Administrator(s).'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63821r3_chk'
  tag severity: 'medium'
  tag gid: 'V-63069'
  tag rid: 'SV-77559r2_rule'
  tag stig_id: 'DTAVSEL-205'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-68987r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
