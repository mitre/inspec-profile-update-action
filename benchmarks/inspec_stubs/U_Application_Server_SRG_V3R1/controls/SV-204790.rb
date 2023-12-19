control 'SV-204790' do
  title 'The application server must provide an immediate warning to the SA and ISSO, at a minimum, when allocated log record storage volume reaches 75% of maximum log record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required.  Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.  Notification of the storage condition will allow administrators to take actions so that logs are not lost.  This requirement can be met by configuring the application server to utilize a dedicated logging tool that meets this requirement.'
  desc 'check', 'Review the configuration settings to determine if the application server logging system provides a warning to the SA and ISSO when 75% of allocated log record storage volume is reached.

If designated alerts are not sent, or the application server is not configured to use a dedicated logging tool that meets this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to provide an alert to the SA and ISSO when allocated log record storage volume reaches 75% of maximum log record storage capacity.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4910r283017_chk'
  tag severity: 'medium'
  tag gid: 'V-204790'
  tag rid: 'SV-204790r508029_rule'
  tag stig_id: 'SRG-APP-000359-AS-000065'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-4910r283018_fix'
  tag 'documentable'
  tag legacy: ['V-57427', 'SV-71699']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
