control 'SV-240262' do
  title 'The web server must use a logging mechanism that is configured to provide a warning to the ISSO and SA when allocated record storage volume reaches 75% of maximum log record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Log processing failures include: software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. 

If log capacity were to be exceeded, then events subsequently occurring would not be recorded. Organizations shall define a maximum allowable percentage of storage capacity serving as an alarming threshold (e.g., web server has exceeded 75% of log storage capacity allocated), at which time the web server or the logging mechanism the web server utilizes will provide a warning to the ISSO and SA at a minimum. 

This requirement can be met by configuring the web server to utilize a dedicated log tool that meets this requirement.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'accesslog.use-syslog' /opt/vmware/etc/lighttpd/lighttpd.conf | grep -v ^#

If the value for "accesslog.use-syslog" is not set to "enable" or is missing, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the lighttpd.conf file with the following: 

accesslog.use-syslog = "enable"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43495r667961_chk'
  tag severity: 'medium'
  tag gid: 'V-240262'
  tag rid: 'SV-240262r879732_rule'
  tag stig_id: 'VRAU-LI-000410'
  tag gtitle: 'SRG-APP-000359-WSR-000065'
  tag fix_id: 'F-43454r667962_fix'
  tag 'documentable'
  tag legacy: ['SV-99949', 'V-89299']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
