control 'SV-80495' do
  title 'Trend Deep Security must notify the system administrator when anomalies in the operation of the security functions are discovered.'
  desc 'If anomalies are not acted upon, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the system administrator is notified when anomalies in the operation of the security functions are discovered.

Verify Intrusion Prevention is enabled for all connected host systems by navigating to Policy >> Policy Editor. 

Navigate to Intrusion Prevention >> General, verify that the intrusion prevention module is "On" and configured with assigned rules.  If "Intrusion Prevention" is not set to "On", this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security sever to notify the system administrator when anomalies in the operation of the security functions are discovered.

To enable Intrusion Prevention functionality on a computer:
In the Policy/Computer editor, go to Intrusion Prevention >> General

Select "On", and then click "Assign/Unassign".

Select the appropriate rules applicable to the information system being monitored.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66653r3_chk'
  tag severity: 'medium'
  tag gid: 'V-66005'
  tag rid: 'SV-80495r1_rule'
  tag stig_id: 'TMDS-00-002125'
  tag gtitle: 'SRG-APP-000474'
  tag fix_id: 'F-72081r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
