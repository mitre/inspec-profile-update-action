control 'SV-80431' do
  title 'Trend Deep Security must update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc "Malicious code includes viruses, worms, Trojan horses, and spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code. Once this code is installed on endpoints within the network, unauthorized users may be able to breach firewalls and gain access to sensitive data.

This requirement applies to applications providing malicious code protection. Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. Malicious code protection mechanisms (including signature definitions and rule sets) must be updated when new releases are available."
  desc 'check', 'Review the Trend Deep Security server configuration to ensure malicious code protection mechanisms are updated whenever new releases are available in accordance with organizational configuration management policy and procedures.

Analyze the system using the Administration >> System Settings >> Updates page. 

Verify that the “Automatically download updates to imported software” option is enabled.

If this option is not enabled, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.

Go to the Administration >> System Settings >> Updates page, and scroll down to Software Updates.

Check the box to enable “Automatically download updates to imported software”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66589r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65941'
  tag rid: 'SV-80431r1_rule'
  tag stig_id: 'TMDS-00-000205'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-72017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
