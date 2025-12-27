control 'SV-95175' do
  title 'The Bromium monitoring module installed on the Bromium Enterprise Controller (BEC) or Bromium vSentry must generate an event and forward to the central log server when anomalies in the operation of security functions of the BEC or Bromium vSentry application are discovered.'
  desc "If anomalies are not acted upon, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Event generation is enabled by default; configuration is required for the BEC server to automatically forward events to the site's event server (e.g., syslog, SIEM)."
  desc 'check', 'Ask the site representatives if they have developed and implemented a solution for forwarding the contents of "worker.log" and "default.log" to a central log server.

If the BEC and Bromium vSentry does not generate an event and forward to the events server when anomalies in the operation of security functions of the BEC or Bromium vSentry application are discovered, this is a finding.'
  desc 'fix', %q(The BEC administrator must work with the site administrator to forward contents of "worker.log" and "default.log" to a central log server in real time.

1. Automatically forward all contents of "worker.log" and "default.log" to the site's centralized log server in real time. 
2. Install the file monitoring agent that is provided by the site's central log server (e.g., syslog, SIEM) and configure to monitor and forward "worker.log" and "default.log" (e.g., C:\Program Data\Bromium\BMS\Logs\default.log). 

Note: Follow the instructions included with the event server.)
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80143r1_chk'
  tag severity: 'low'
  tag gid: 'V-80471'
  tag rid: 'SV-95175r1_rule'
  tag stig_id: 'BROM-00-001155'
  tag gtitle: 'SRG-APP-000474'
  tag fix_id: 'F-87277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
