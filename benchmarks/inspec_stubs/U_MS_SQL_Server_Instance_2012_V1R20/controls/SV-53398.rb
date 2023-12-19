control 'SV-53398' do
  title 'SQL Server itself, or the logging or alerting mechanism the application utilizes, must provide a warning when allocated audit record storage volume reaches an organization-defined percentage of maximum audit record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Audit processing failures include:  software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

If audit log capacity were to be exceeded, then events subsequently occurring will not be recorded. Organizations shall define a maximum allowable percentage of storage capacity serving as an alarming threshold (e.g., application has exceeded 80% of log storage capacity allocated) at which time the application or the logging mechanism the application utilizes will provide a warning to the appropriate personnel.

A failure of database auditing will result in either the database continuing to function without auditing, or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions. This can be an alert provided by a log repository or the OS when a designated log directory is nearing capacity.'
  desc 'check', 'Since SQL Server does not support the monitoring of the available audit log file space, utilize Windows File Server Resource Manager or a third-party application to perform this activity.

From a Command Prompt, open fsrm.msc.
If fsrm.msc is not installed, the File Server Resource Manager is not installed, File and Folder Quota Management is not enabled. If File Server Resource Manager or a third-party tool capable of sending alert notifications based on audit log store requirements is not installed, this is a finding.

If fsrm.msc is installed, expand File Server Resource Manager in the left pane.
Expand Quota Management.
Select Quotas.
If Quotas have not been created for defined Audit Log storage locations that meet organizationally defined requirements, this is a finding.

In the center pane, select each quota to determine its Path, Limit, Type, and Description. 

Right click the appropriate quota or quotas, and click Edit Quota Properties.
Examine the Notification thresholds panel. If there are no Notification thresholds applied to this Quota, this is a finding.
If a Notification Threshold is applied, and it does not send an email alert, or provide an Event Log entry which is handled by an automated Log Alert reporting application, this is a finding.

If a third-party application is utilized to fulfill this requirement, and it is not configured to provide a notification, this is a finding.'
  desc 'fix', 'From File Server Resource Manager:  Choose the From Server Selection, Select a server from the server pool, and select the server from the lower menu. Expand the File and Storage Services Role. Then Expand the File and iSCSI Services subtree. Select File Server Resource Manager. Click Add Features. Return to Add Roles and Features Wizard. Click Next. On the Features Tab, Click Next. Click Install to install and enable the FSRM.msc Microsoft Management Console Snap-in tool.
From a Command Prompt, open fsrm.msc. Enable File and Folder Quota Management. 
Create Quotas for previously identified Audit storage locations based on organizationally defined requirements.

Right click the appropriate quota or quotas, and click Edit Quota Properties. From the Notification thresholds pane, create a Notification threshold for this Quota utilizing a generate email alert, or a generated Event Log entry.'
  impact 0.3
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47640r2_chk'
  tag severity: 'low'
  tag gid: 'V-41023'
  tag rid: 'SV-53398r2_rule'
  tag stig_id: 'SQL2-00-012600'
  tag gtitle: 'SRG-APP-000103-DB-000050'
  tag fix_id: 'F-46322r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
