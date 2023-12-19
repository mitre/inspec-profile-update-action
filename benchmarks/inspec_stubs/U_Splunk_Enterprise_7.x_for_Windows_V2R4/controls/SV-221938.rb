control 'SV-221938' do
  title 'Splunk Enterprise idle session timeout must be set to not exceed 15 minutes.'
  desc 'Automatic session termination after a period of inactivity addresses the potential for a malicious actor to exploit the unattended session. Closing any unattended sessions reduces the attack surface to the application.'
  desc 'check', 'Select Settings >> Server Settings >> General Settings and verify that Session timeout is set to 15 minutes or less.

If Splunk is not configured to 15 minutes or less, this is a finding.'
  desc 'fix', 'Select Settings >> Server Settings >> General Settings and set Session timeout to 15 minutes or less.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23652r420282_chk'
  tag severity: 'medium'
  tag gid: 'V-221938'
  tag rid: 'SV-221938r879673_rule'
  tag stig_id: 'SPLK-CL-000190'
  tag gtitle: 'SRG-APP-000295-AU-000190'
  tag fix_id: 'F-23641r420283_fix'
  tag 'documentable'
  tag legacy: ['SV-111367', 'V-102423']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
