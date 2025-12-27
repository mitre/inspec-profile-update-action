control 'SV-222625' do
  title 'Execution flow diagrams and design documents must be created to show how deadlock and recursion issues in web services are being mitigated.'
  desc 'In order to understand data flows within web services, the process flow of data must be developed and documented.

There are several different ways that web service deadlock occurs, many times it is due to when a client invokes a synchronous method on a web service, the client will block waiting for the method to complete. If attempts to call the client (invoke a callback) while the client is waiting for the original method to complete, then each party will deadlock waiting for the other.

This is referred to as deadlock. The same situation could occur if a callback handler attempted to call a synchronous method on its caller.

Applications that utilize web services must account for and document how they deal with a deadlock issue. This can be accomplished by documenting data flow and specifically accounting for the risk in the design of the application.'
  desc 'check', 'Review the application documentation and the system diagrams detailing application system to system and service to service communication methods.

Interview the application admin to identify any application web services that are deployed by the application.

If the application does not deploy web services, the requirement is not applicable.

If the application consumes web services but is not responsible for development of the services, the requirement is not applicable.

Review the data flow diagrams and the system documentation to determine if the issue of web service deadlock is addressed.

If the issue is not addressed in the documentation or configuration settings, ask the application admin to demonstrate how deadlock issues are addressed.

If deadlock issues are not being addressed via documented web service configuration or design, this is a finding.'
  desc 'fix', 'Develop web services to account for deadlock issues.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24295r493783_chk'
  tag severity: 'medium'
  tag gid: 'V-222625'
  tag rid: 'SV-222625r508029_rule'
  tag stig_id: 'APSC-DV-002950'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24284r493784_fix'
  tag 'documentable'
  tag legacy: ['SV-84929', 'V-70307']
  tag cci: ['CCI-000366', 'CCI-000336']
  tag nist: ['CM-6 b', 'CM-4 (2)']
end
