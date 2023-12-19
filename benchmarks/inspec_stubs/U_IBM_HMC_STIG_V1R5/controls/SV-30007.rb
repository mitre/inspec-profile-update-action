control 'SV-30007' do
  title 'Dial-out access from the Hardware Management Console Remote Support Facility (RSF) must be restricted to an authorized vendor site.'
  desc 'Dial-out access from the Hardware Management Console could impact the integrity of the environment, by enabling the possible introduction of spyware or other malicious code. It is important to note that it should be properly configured to only go to an authorized vendor site. Note: This feature will  be activated for Non-Classified Systems only.  Also, many newer processors (e.g., zEC12/zBC12 processors) will not have modems.  If there is no modem, this check is not applicable.'
  desc 'check', 'Whenever dial-out hardware is present, have the System Administrator or Systems Programmer validate that dial-out access from the Hardware Management Console is enabled for any non-classified system.

Note: This is accomplished by going to Hardware Management Console and selecting Customize Remote Services. Then verify that Enable Remote Services is active.

If automatic dial-out access from the Hardware Management Console is enabled, have the Systems Administrator or Systems Programmer validate that remote phone number and remote service parameters values are valid authorized venders in the remote Service Panel of the Hardware Management Console. 

If all the above values are not correct, this is a finding.'
  desc 'fix', 'When this feature is turned on for non-classified systems, the site must verify that the remote site information is valid.

The RSF, which is also commonly referred to as call home, is one of the key components that contributes to zero downtime on System z hardware.

The Hardware Management Console RSF provides communication to an IBM support network, known as RETAIN for hardware problem reporting and service.
When a Hardware Management Console enables RSF, the Hardware Management Console then becomes a call home server. 
The types of communication that are provided are:

- Problem reporting and repair data.
- Fix delivery to the service processor and Hardware Management Console.
- Hardware inventory data.
- System updates that are required to activate Capacity on Demand changes.

The following call home security characteristics are in effect regardless of the connectivity method that is chosen:
RSF requests are always initiated from the Hardware Management Console to IBM. An inbound connection is never initiated from the IBM Service Support System.
All data that is transferred between the Hardware Management Console and the IBM Service Support System is encrypted in a high-grade Secure Sockets Layer (SSL) encryption.
When initializing the SSL-encrypted connection, the Hardware Management Console validates the trusted host by its digital signature issued for the IBM Service Support system. Data sent to the IBM Service Support System consists solely of hardware problems and configuration data. No application or customer data is transmitted to IBM.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29552r2_chk'
  tag severity: 'medium'
  tag gid: 'V-24348'
  tag rid: 'SV-30007r3_rule'
  tag stig_id: 'HMC0030'
  tag gtitle: 'HMC0030'
  tag fix_id: 'F-26666r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Security Manager', 'Systems Programmer']
  tag ia_controls: 'EBRP-1, EBRU-1'
  tag cci: ['CCI-002883']
  tag nist: ['MA-3 (4)']
end
