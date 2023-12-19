control 'SV-225641' do
  title 'The Samsung SDS EMM must be configured to communicate the following commands to the MDM Agent: read audit logs kept by the MD.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For audit logs to be useful, administrators must have the ability to view them.

SFR ID: FMT_SMF.1.1(1) #19'
  desc 'check', 'Use the following procedure to verify the command to read audits to the MDM Agent has been configured on the SDS EMM server:  

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Service Overview >> Log and Event >> Audit Log. 
3. Verify all audit events with audit type of "Device" have been selected.
 
If the command for reading audits to the MDM Agent has not been configured on the SDS EMM server, this is a finding.'
  desc 'fix', 'Use the following instructions to verify the command has been configured to read audits to the MDM Agent on the SDS EMM server:

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Service Overview >> Log and Event >> Audit Event. 
3. Select all audit events with audit type of "Device" and click the "Save" button.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27342r560947_chk'
  tag severity: 'medium'
  tag gid: 'V-225641'
  tag rid: 'SV-225641r588007_rule'
  tag stig_id: 'SSDS-00-000110'
  tag gtitle: 'PP-MDM-411009'
  tag fix_id: 'F-27330r560948_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
