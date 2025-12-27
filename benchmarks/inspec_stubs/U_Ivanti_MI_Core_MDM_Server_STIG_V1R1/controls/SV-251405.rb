control 'SV-251405' do
  title 'The Ivanti MobileIron Core server must back up audit records at least every seven days onto a log management server.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media from the system being audited on an organizationally defined frequency helps ensure, in the event of a catastrophic system failure, the audit records will be retained.

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions.

'
  desc 'check', 'Verify that Splunk is configured for automated log export.

Step 1: Verify the Splunk Forwarder is enabled.
1. Log in to System Manager.
2. Go to Settings >> Services.
3. Verify that the "Enable" toggle is ON and "Running" is displayed.
If "Enable" toggle is not ON or "Running" is not displayed, this is a finding.

Step 2: Verify that Splunk Indexer is configured.
1. Log in to System Manager.
2. Go to Settings >> Data Export >> Splunk Indexer.
3. Verify that there is an entry and the Status is "Connected".
If there is no entry for Splunk Indexer or the Status is "Not Connected", this is a finding.

Step 3: Verify "Audit Log" is enabled in the Splunk "data to index".
1. Log in to System Manager.
2. Go to Settings >> Data Export >> Splunk Data to open the "Data to Index" window.
3. Verify "Audit Log" is included in the "Data To Index".
If "Audit Log" is not included in the "Data To Index", this is a finding.

Note: Syslog can be used instead of Splunk.'
  desc 'fix', 'Complete the following activities to configure the transfer of MobileIron Core 10 server logs:

Configure Splunk for automated log export:

Step 1: Enable Core to turn on the Splunk Forwarder so it can push data to the Splunk Indexer.

To enable the Splunk Forwarder:
1. Log in to System Manager.
2. Go to Settings >> Services.
3. Select "Enable" next to Splunk Forwarder.
4. Click Apply >> OK to save the changes.

Step 2: Add a Splunk Indexer to configure which external Splunk Indexer will receive and manipulate the data from the Splunk Forwarder.

To add a Splunk Indexer:
1. Log in to System Manager.
2. Go to Settings >> Data Export >> Splunk Indexer.
3. Click "Add" to open the Add Splunk Indexer window.
4. Modify the fields as necessary in the "Add Splunk Indexer" window. The following are fields and descriptions in the Add Splunk Indexer window:
- Splunk Indexer - Add the IP address of your Splunk Enterprise Server.
- Port - Add the port of your Splunk Enterprise Server.
- Enable SSL - Click this check box to enable SSL.
5. Click Apply >> OK to save the changes.

Step 3: Configure Splunk Data to configure which data Splunk Forwarder sends to the Splunk Indexer.

To configure Splunk Data:
1. Log in to System Manager.
2. Go to Settings >> Data Export >> Splunk Data to open the "Data to Index" window.
3. Modify the fields as necessary.
- Click "Show/Hide Advanced Options" to further customize which data to send to Splunk.
- Check "Audit Log" at a minimum.
4. Click Apply >> OK.
5. Restart the Splunk Forwarder by disabling it and then enabling it again.
  a. Go to Settings >> Services.
  b. Select "Disable" next to Splunk Forwarder.
  c. Click Apply >> OK.
  d. Select "Enable" next to Splunk Forwarder.
6. Click Apply >> OK to save the changes.

Note: Syslog can be used instead of Splunk.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54840r806345_chk'
  tag severity: 'medium'
  tag gid: 'V-251405'
  tag rid: 'SV-251405r806347_rule'
  tag stig_id: 'IMIC-11-003500'
  tag gtitle: 'SRG-APP-000125-UEM-000074'
  tag fix_id: 'F-54793r806346_fix'
  tag satisfies: ['FAU_STG_EXT.1.1', 'FMT_SMF.1.1(2) Refinement b']
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
