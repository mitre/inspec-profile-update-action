control 'SV-101913' do
  title 'The MobileIron Core v10 server must be configured to transfer MobileIron Core v10 server logs to another server for storage, analysis, and reporting. Note: MobileIron Core v10 server logs include logs of MDM events and logs transferred to the MobileIron Core v10 server by MDM agents of managed devices.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. Since the MobileIron Core v10 server has limited capability to store mobile device log files and perform analysis and reporting of mobile device log files, the MobileIron Core v10 server must have the capability to transfer log files to an audit log management server.

SFR ID: FMT_SMF.1.1(2) h, FAU_STG_EXT.1.1(1)'
  desc 'check', 'Verify that Splunk is configured for automated log export.

Step 1: Verify that the "Splunk Forwarder" is "Enabled".
1. Log onto System Manager.
2. Go to Settings >> Services.
3. Verify that the "Enable" toggle is "ON" and "Running" is displayed.

If "Enable" toggle is not "ON" or "Running" is not displayed, this is a finding.

Step 2: Verify that "Splunk Indexer" is configured.
1. Log onto System Manager.
2. Go to Settings >> Data Export >> Splunk Indexer.
3. Verify that there is an entry and the Status is "Connected".

If there is no entry for "Splunk Indexer" or the Status is "Not Connected", this is a finding.

Step 3: Verify "Audit Log" is enabled in the Splunk "Data to Index".
1. Log onto System Manager.
2. Go to Settings >> Data Export >> Splunk Data to open the "Data to Index" window.
3. Verify "Audit Log" is included in the "Data to Index".

If "Audit Log" is not included in the "Data to Index", this is a finding.'
  desc 'fix', 'Complete the following activities to configure the transfer of MobileIron Core v10 server logs.

Configure Splunk for automated log export.

Step 1: Enable Core to turn on the "Splunk Forwarder" so it can push data to the "Splunk Indexer".
To enable the "Splunk Forwarder":
1. Log onto System Manager.
2. Go to Settings >> Services.
3. Select "Enable" next to "Splunk Forwarder".
4. Click "Apply".
5. Click "OK" to save the changes.

Step 2: Adding a "Splunk Indexer" to configure which external "Splunk Indexer" will receive and manipulate the data from the "Splunk Forwarder".
To add a "Splunk Indexer":
1. Log onto System Manager.
2. Go to Settings >> Data Export >> Splunk Indexer.
3. Click "Add" to open the "Add Splunk Indexer" window.
4. Modify the fields, as necessary, in the "Add Splunk Indexer" window.
The following table summarizes fields and descriptions in the Add Splunk Indexer window:
Fields, Description, Splunk Indexer, add the IP address of your Splunk Enterprise Server, Port, add port of your Splunk Enterprise Server, and enable "SSL"; click this checkbox to enable "SSL".
5. Click "Apply".
6. Click "OK" to save the changes.

Step 3: Configuring Splunk Data to configure which data "Splunk Forwarder" sends to the "Splunk Indexer".
To configure Splunk Data:
1. Log onto System Manager.
2. Go to Settings >> Data Export >> Splunk Data to open the "Data to Index" window.
3. Modify the fields, as necessary.
Click "Show/Hide" Advanced Options to further customize which data to send to Splunk; check "Audit Log" at a minimum.
4. Click Apply.
5. Click "OK".
6. Restart the "Splunk Forwarder" by disabling it, then enabling it again.
a. Go to Settings >> Services.
b. Select "Disable" next to "Splunk Forwarder".
c. Click "Apply".
d. Click "OK".
e. Select "Enable" next to "Splunk Forwarder".
7. Click "Apply".
8. Click "OK" to save the changes.'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90969r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91811'
  tag rid: 'SV-101913r1_rule'
  tag stig_id: 'MICR-10-000510'
  tag gtitle: 'PP-MDM-311054'
  tag fix_id: 'F-98013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
