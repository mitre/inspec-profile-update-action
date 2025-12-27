control 'SV-222475' do
  title 'When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.'
  desc "Without establishing the source, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In the case of centralized logging, or other instances where log files are consolidated, there is risk that the application's log data could be co-mingled with other log data.  To address this issue, the application itself must be identified as well as the application host or client name. 

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging.

Associating information about the source of the event within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application."
  desc 'check', 'If the application is logging locally and does not utilize a centralized logging solution, this requirement is not applicable.

Review system documentation and identify log location.  Access the application logs.

Review the application logs.

Ensure the application is uniquely identified either within the logs themselves or via log storage mechanisms.

Ensure the hosts or client names hosting the application are also identified.  Either hostname or IP address is acceptable.

If the application name and the hosts or client names are not identified, this is a finding.'
  desc 'fix', 'Configure the application logs or the centralized log storage facility so the application name and the hosts hosting the application are uniquely identified in the logs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24145r493333_chk'
  tag severity: 'medium'
  tag gid: 'V-222475'
  tag rid: 'SV-222475r879566_rule'
  tag stig_id: 'APSC-DV-001000'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-24134r493334_fix'
  tag 'documentable'
  tag legacy: ['V-69433', 'SV-84055']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
