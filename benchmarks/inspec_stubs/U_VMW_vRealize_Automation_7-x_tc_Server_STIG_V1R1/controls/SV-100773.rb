control 'SV-100773' do
  title 'tc Server ALL must use a logging mechanism that is configured to provide a warning to the ISSO and SA when allocated record storage volume reaches 75% of maximum log record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Log processing failures include: software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. 

If log capacity were to be exceeded, then events subsequently occurring would not be recorded. Organizations must define a maximum allowable percentage of storage capacity serving as an alarming threshold (e.g., web server has exceeded 75% of log storage capacity allocated), at which time the web server or the logging mechanism the web server utilizes will provide a warning to the ISSO and SA at a minimum. 

This requirement can be met by configuring the web server to utilize a dedicated log tool that meets this requirement.'
  desc 'check', 'Interview the ISSO.

Review site documentation and system configuration. Determine if the system has a logging mechanism that will provide a warning to the ISSO and SA when allocated record storage volume reaches 75% of maximum log record storage capacity.

If such an alert mechanism is not in use, this is a finding.'
  desc 'fix', 'Configure the tc Server ALL logging mechanism to alert the ISSO / SA when the logs have reached 75% of storage capacity.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90123'
  tag rid: 'SV-100773r1_rule'
  tag stig_id: 'VRAU-TC-000755'
  tag gtitle: 'SRG-APP-000359-WSR-000065'
  tag fix_id: 'F-96865r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
