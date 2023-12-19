control 'SV-69563' do
  title 'The IDPS must immediately use updates made to policy filters, rules, signatures, and anomaly analysis algorithms for traffic detection and prevention functions.'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the PPSM CAL, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.

Changes to the IDPS must take effect when made by an authorized administrator and the new configuration is put in place or committed, including upon restart or the application or reboot of the system. With some devices, the changes take effect as the configuration is changed, while with others, the new configuration must be submitted to the device. In any case, the behavior of the IDPS must immediately be affected to reflect the configuration change.'
  desc 'check', 'Verify the IDPS immediately uses updates made to policy filters, rules, signatures, and anomaly analysis algorithms for traffic detection and prevention functions.

If the IDPS does not immediately use updates made to policy filters, rules, signatures, and anomaly analysis algorithms to traffic detection and prevention functions, this is a finding.'
  desc 'fix', 'Configure the IDPS to immediately use updates made to policy filters, rules, signatures, and anomaly analysis algorithms for traffic detection and prevention functions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55939r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55317'
  tag rid: 'SV-69563r1_rule'
  tag stig_id: 'SRG-NET-000019-IDPS-00187'
  tag gtitle: 'SRG-NET-000019-IDPS-00187'
  tag fix_id: 'F-60183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
