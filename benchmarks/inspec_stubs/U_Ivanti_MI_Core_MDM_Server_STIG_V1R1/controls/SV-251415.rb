control 'SV-251415' do
  title 'The Ivanti MobileIron Core server must be configured to transfer Ivanti MobileIron Core server logs to another server for storage, analysis, and reporting. Note: Ivanti MobileIron Core server logs include logs of UEM events and logs transferred to the Ivanti MobileIron Core server by UEM agents of managed devices.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

Note: UEM server logs include logs of UEM events and logs transferred to the UEM server by UEM agents of managed devices.

'
  desc 'check', 'Verify that Splunk is configured for automated log export.

Step 1: Verify that the Splunk Forwarder is enabled.
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
4. Modify the fields, as necessary, in the "Add Splunk Indexer" window. The following fields and descriptions are in the Add Splunk Indexer window:
- Splunk Indexer - Add the IP address of your Splunk Enterprise Server.
- Port - Add port of your Splunk Enterprise Server.
- Enable SSL - Click this check box to enable SSL.
5. Click Apply >> OK to save the changes.

Step 3: Configure Splunk Data to configure which data Splunk Forwarder sends to the Splunk Indexer.

To configure Splunk Data:
1. Log in to System Manager.
2. Go to Settings >> Data Export >> Splunk Data to open the "Data to Index" window.
3. Modify the fields, as necessary.
- Click Show/Hide Advanced Options to further customize which data to send to Splunk.
- Check "Audit Log" at a minimum.
4. Click Apply >> OK.
5. Restart the Splunk Forwarder by disabling it, then enabling it again.
  a. Go to Settings >> Services.
  b. Select Disable next to Splunk Forwarder.
  c. Click Apply >> OK.
  d. Select Enable next to Splunk Forwarder.
6. Click Apply >> OK to save the changes.

Note: Syslog can be used instead of Splunk.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54850r806375_chk'
  tag severity: 'medium'
  tag gid: 'V-251415'
  tag rid: 'SV-251415r810417_rule'
  tag stig_id: 'IMIC-11-008600'
  tag gtitle: 'SRG-APP-000358-UEM-000228'
  tag fix_id: 'F-54803r810416_fix'
  tag satisfies: ['FMT_SMF.1.1(2) c.8', 'FAU_STG_EXT.1.1(1) \nReference: PP-MDM-411054']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
