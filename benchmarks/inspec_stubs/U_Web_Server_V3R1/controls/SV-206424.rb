control 'SV-206424' do
  title 'The web server must use a logging mechanism that is configured to provide a warning to the ISSO and SA when allocated record storage volume reaches 75% of maximum log record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Log processing failures include: software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. 

If log capacity were to be exceeded, then events subsequently occurring would not be recorded. Organizations shall define a maximum allowable percentage of storage capacity serving as an alarming threshold (e.g., web server has exceeded 75% of log storage capacity allocated), at which time the web server or the logging mechanism the web server utilizes will provide a warning to the ISSO and SA at a minimum. 

This requirement can be met by configuring the web server to utilize a dedicated log tool that meets this requirement.'
  desc 'check', 'Review the web server documentation and deployment configuration settings to determine if the web server log system provides a warning to the ISSO and SA when allocated record storage volume reaches 75% of maximum record storage capacity.

If designated alerts are not sent or the web server is not configured to use a dedicated log tool that meets this requirement, this is a finding.'
  desc 'fix', 'Configure the web server to provide a warning to the ISSO and SA when allocated log record storage volume reaches 75% of maximum record storage capacity.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6685r377864_chk'
  tag severity: 'medium'
  tag gid: 'V-206424'
  tag rid: 'SV-206424r855046_rule'
  tag stig_id: 'SRG-APP-000359-WSR-000065'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-6685r377865_fix'
  tag 'documentable'
  tag legacy: ['SV-70229', 'V-55975']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
