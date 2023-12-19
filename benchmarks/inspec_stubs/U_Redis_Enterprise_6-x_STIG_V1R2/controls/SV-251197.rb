control 'SV-251197' do
  title 'Redis Enterprise DBMS must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', 'To verify that Redis Enterprise has been configured to send appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity:
1. Log in to the Redis Enterprise UI as a user with the Admin role.
2. Navigate to the Settings tab and then to Alerts.
3. Verify that the appropriate Alerts are enabled to notify support staff when storage volume reaches 75 percent.
4. Navigate to the General subtab and scroll down to verify that an email server is set up to send out alert notifications.
5. Lastly, navigate to the Access Control tab and verify that the appropriate users listed are configured to receive alert notifications.

To view on a specific database:
1. Navigate to the Databases tab on the UI.
2. Select the Databases from the list and then select configuration.
3. Scroll down to view the Alert settings.

Also verify that the RHEL server OS is STIG compliant to notify support staff when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

If appropriate support staff are not notified immediately upon storage volume utilization reaching 75 percent, this is a finding.'
  desc 'fix', 'To configure cluster alerts:
1. Log in to the Redis Enterprise AdminUI (repeat this step for the following sections as well).
2. Navigate to settings >> alerts. Alerts may be enabled for node or cluster events, such as high memory usage or throughput.

Configurable alerts may be displayed as follows:
- As a warning icon for the node and cluster
- In the logs 
- In email notifications, if email alerts are configured
Note: If alerts are enabled for "Node joined" or "Node removed" actions,  "Receive email alerts" must also be enabled so the notifications are sent.

To enable alerts for a cluster:
In settings >> alerts, select the desired alerts to show for the cluster and click "Save".

Database alerts: 
For each database, alerts may be enabled for database events, such as high memory usage or throughput.

Configured alerts are shown:
- As a warning icon (Warning) for the database
- In the log
- In emails, if email alerts are configured

To enable alerts for a database:
1. In configuration for each database, click show advanced options to view and select the database alerts.
2. Click "Update".

To send cluster or database alerts by email:
1. Log in to the Redis Enterprise UI.
2. Navigate to settings >> alerts, then select Receive email alerts at the bottom of the page.
3. Configure the email server settings.
4. In access control, select for each user the database and cluster alerts that are to be received by the user.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54632r855605_chk'
  tag severity: 'medium'
  tag gid: 'V-251197'
  tag rid: 'SV-251197r855606_rule'
  tag stig_id: 'RD6X-00-005700'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-54586r804780_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
