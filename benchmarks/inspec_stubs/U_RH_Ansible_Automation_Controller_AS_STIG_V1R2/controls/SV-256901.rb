control 'SV-256901' do
  title 'Automation Controller must allocate log record storage capacity and shut down by default upon log failure (unless availability is an overriding concern).'
  desc 'It is critical that when a system is at risk of failing to process logs, it detects and takes action to mitigate the failure. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. During a failure, the application server must be configured to shut down unless the application server is part of a high availability system.

When availability is an overriding concern, other approved actions in response to a log failure are as follows: 

(i) If the failure was caused by the lack of log record storage capacity, the application must continue generating log records if possible (automatically restarting the log service if necessary), overwriting the oldest log records in a first-in-first-out manner.

(ii) If log records are sent to a centralized collection server and communication with this server is lost or the server fails, the application must queue log records locally until communication is restored or until the log records are retrieved manually. Upon restoration of the connection to the centralized collection server, action must be taken to synchronize the local log data with the collection server.

'
  desc 'check', 'Administrator must check, for each Automation Controller host, the rsyslog configuration to verify the log rollover against an organizationally defined log capture size.

Check LOG_AGGREGATOR_MAX_DISK_USAGE_GB field in the Automation Controller configuration.

On the host, execute:

awx-manage print_settings LOG_AGGREGATOR_MAX_DISK_USAGE_GB

If this field is not set to the organizationally defined log capture size, this is a finding.

Check LOG_AGGREGATOR_MAX_DISK_USAGE_PATH field in the Automation Controller configuration for the log file location to "/var/lib/awx".

On the host, execute:
awx-manage print_settings LOG_AGGREGATOR_MAX_DISK_USAGE_PATH 

If this field is not set to "/var/lib/awx", this is a finding.'
  desc 'fix', %q(Open a web browser and navigate to: https://<Automation Controller server>/api/v2/settings/logging/

(If the "Log In" button is displayed, click it, enter an Automation Controller administrator's credentials, and continue.)

In the Content section, modify the following values:

LOG_AGGREGATOR_MAX_DISK_USAGE_GB  = organization-defined requirement for log buffering.

LOG_AGGREGATOR_MAX_DISK_USAGE_PATH  = "/var/lib/awx"

Click "PUT".)
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60576r927140_chk'
  tag severity: 'medium'
  tag gid: 'V-256901'
  tag rid: 'SV-256901r927265_rule'
  tag stig_id: 'APAS-AT-000031'
  tag gtitle: 'SRG-APP-000109-AS-000068'
  tag fix_id: 'F-60518r927141_fix'
  tag satisfies: ['SRG-APP-000109-AS-000068', 'SRG-APP-000357-AS-000038']
  tag 'documentable'
  tag cci: ['CCI-000140', 'CCI-001849']
  tag nist: ['AU-5 b', 'AU-4']
end
