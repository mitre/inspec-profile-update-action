control 'SV-68631' do
  title 'The ALG must immediately use updates made to policy enforcement mechanisms such as policy filters, rules, signatures, and analysis algorithms for gateway and/or intermediary functions.'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the PPSM CAL, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.

Changes to the ALG must take effect when made by an authorized administrator and the new configuration is put in place or committed, including upon restart or the application or reboot of the system. With some devices, the changes take effect as the configuration is changed, while with others, the new configuration must be submitted to the device. In any case, the behavior of the ALG must immediately be affected to reflect the configuration change.'
  desc 'check', 'Verify the ALG immediately uses updates made to policy enforcement mechanisms such as policy filters, rules, signatures, and analysis algorithms for gateway and/or intermediary functions.

If the ALG does not immediately use updates made to policy enforcement mechanisms such as policy filters, rules, signatures, and analysis algorithms for gateway and/or intermediary functions, this is a finding.'
  desc 'fix', 'Configure the ALG to immediately use updates made to policy enforcement mechanisms such as policy filters, rules, signatures, and analysis algorithms for gateway and/or intermediary functions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54385'
  tag rid: 'SV-68631r1_rule'
  tag stig_id: 'SRG-NET-000019-ALG-000019'
  tag gtitle: 'SRG-NET-000019-ALG-000019'
  tag fix_id: 'F-59239r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
