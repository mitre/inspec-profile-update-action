control 'SV-89673' do
  title 'The MQ Appliance network device must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The MQ Appliance network device must use an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891. 

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. 

On the Manage Appliance tab, select Network >> Interface/NTP Service. 

Verify: 
- NTP server destinations are configured; 
* The NTP servers are located in different geographic regions; and 
* Status (at the top of the page) is "up". 

If any is not true, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. 

Click on the Network icon (third from the top). 
Select "Interface/NTP Service". 
Click the "Add" button to add multiple NTP servers. 
Click "Enable administrative state". 
Click the "Apply" button. 

Add one or more additional NTP servers, at least one of which is from a different geographic region. 

The result should be: "Status:up" 

Click "Save configuration".'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74999'
  tag rid: 'SV-89673r1_rule'
  tag stig_id: 'MQMH-ND-001080'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-81615r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
