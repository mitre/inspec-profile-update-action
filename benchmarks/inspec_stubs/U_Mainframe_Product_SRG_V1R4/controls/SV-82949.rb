control 'SV-82949' do
  title 'The Mainframe Product must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Applications or systems that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption of mission-essential processes. 

In general, application security mechanisms should be designed so that a failure will follow the same execution path as disallowing the operation. For example, security methods, such as is Authorized(), is Authenticated(), and validate(), should all return false if there is an exception during processing. If security controls can throw exceptions, they must be very clear about exactly what that condition means. 

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Examine installation and configuration settings.

If the Mainframe Product is not configured to secure all processes to a secure state (i.e., not allowing access to protected privileges and procedures in the event of failure), this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to secure all processes to a secure state (i.e., not allowing access to protected privileges and procedures in the event of failure).'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68991r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68459'
  tag rid: 'SV-82949r1_rule'
  tag stig_id: 'SRG-APP-000225-MFP-000300'
  tag gtitle: 'SRG-APP-000225-MFP-000300'
  tag fix_id: 'F-74575r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
