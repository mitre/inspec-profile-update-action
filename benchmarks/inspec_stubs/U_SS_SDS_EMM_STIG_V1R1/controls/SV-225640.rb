control 'SV-225640' do
  title 'The Samsung SDS EMM must implement functionality to generate an audit record of the following auditable events:
c. [selection: Commands issued to the MDM Agent].'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For audit logs to be useful, administrators must have the ability to view them.

SFR ID: FAU_GEN.1.1(1)'
  desc 'check', 'Use the following procedure to verify logging of all commands issued to the MDM Agent has been configured on the SDS EMM server:  

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Service Overview >> Log and Event >> Audit Event. 
3. Verify all audit events with Type as "Server" and Event Category as "Device Command" have been selected. 

If logging of all commands issued to the MDM Agent has not been configured on the SDS EMM server, this is a finding.'
  desc 'fix', 'Use the following instructions to configure logging of all commands issued to the MDM Agent on the SDS EMM server:    

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Service Overview >> Log and Event >> Audit Event. 
3. Select Type as "Server" and Event Category as "Device Command". 
4. Check the audit target and click the "Save" button at the top of the page.'
  impact 0.3
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27341r547705_chk'
  tag severity: 'low'
  tag gid: 'V-225640'
  tag rid: 'SV-225640r547707_rule'
  tag stig_id: 'SSDS-00-000010'
  tag gtitle: 'PP-MDM-412000'
  tag fix_id: 'F-27329r547706_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
