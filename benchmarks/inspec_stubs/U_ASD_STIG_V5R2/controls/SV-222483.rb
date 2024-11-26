control 'SV-222483' do
  title 'The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion.

Due to variances in application usage and audit records storage usage, the SA and the ISSO may evaluate usage patterns and determine if a higher percentage of usage is warranted before an alarm is sent.  The intent of the requirement is to provide a warning that will allow the SA and ISSO ample time to plan and implement an audit storage capacity expansion that will provide for the increased audit log storage requirements without forcing an emergency or otherwise negatively impacting the recording of audit events.

The requirement will take into account a reasonable amount of processing time such as 1 or 2 minutes that may be required of the system in order to satisfy the requirement.'
  desc 'check', 'Review system documentation and interview application administrator for details regarding logging configuration. 

If the application utilizes a centralized logging system that provides storage capacity alarming, this requirement is not applicable.

Identify application alarming capability relating to storage capacity alarming for the log repository. Coordinate with the appropriate personnel regarding the generation of test alarms.

Review log alarm settings and ensure audit log storage capacity alarming is enabled and set to alarm when the storage threshold exceeds 75% of disk storage capacity or the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.

Ensure the alarm will be sent to the ISSO and the application administrator when the utilization threshold is exceeded by changing the threshold settings to below the current disk space utilization. An alarm should be triggered at that point and forwarded to the ISSO and the SA/application admin.

If the application is not configured to send an alarm when storage volume exceeds 75% of disc capacity or if the designated alarm recipients did not receive an alarm when the test was conducted, this is a finding.'
  desc 'fix', 'Configure the application to send an immediate alarm to the application admin/SA and the ISSO when the allocated log storage capacity exceeds 75% of usage or exceeds the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36239r602282_chk'
  tag severity: 'medium'
  tag gid: 'V-222483'
  tag rid: 'SV-222483r865216_rule'
  tag stig_id: 'APSC-DV-001090'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-36205r865216_fix'
  tag 'documentable'
  tag legacy: ['SV-84071', 'V-69449']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
