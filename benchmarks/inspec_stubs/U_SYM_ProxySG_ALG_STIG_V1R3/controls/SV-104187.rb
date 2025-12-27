control 'SV-104187' do
  title 'Symantec ProxySG must immediately use updates made to policy enforcement mechanisms such as policies and rules.'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the PPSM CAL, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.

Changes to the ALG must take effect when made by an authorized administrator and the new configuration is put in place or committed, including upon restart of the application or reboot of the system. With some devices, the changes take effect as the configuration is changed, while with others, the new configuration must be submitted to the device. In any case, the behavior of the ALG must immediately be affected to reflect the configuration change.

In the ProxySG platform, a policy contains one or more layers that provide functionality, such as SSL interception, authentication, and web access. Each layer contains rules that define source and destination criteria and an action to take for each set of criteria.'
  desc 'check', %q(Verify that ProxySG is configured to restrict access to suspicious or harmful communications.

1. Log on to the Web Management Console.
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, click into each Web Access and SSL Access Layer.
4. Within each layer above, review each rule and verify that the "Destination" fields are not set to "Any" and that they contain URL categories and/or threat risk levels that should be blocked per the organization's security policy.

If Symantec ProxySG does not immediately use updates made to policy enforcement mechanisms such as policies and rules, this is a finding.)
  desc 'fix', %q(Configure ProxySG to restrict access to suspicious or harmful communications.

1. Log on to the Web Management Console.
2. Click Configuration >> Content Filtering.
3. Under "General," verify that at least one "Provider" is enabled.
4. Click Configuration >> Visual Policy Manager. 
5. Click "Launch". While in the Visual Policy Manager, click into each Web Access and SSL Access Layer.
6. Within each layer above, right-click the "Destination" fields of each rule, click "set", and specify URL categories and/or threat risk levels that should be blocked per the organization's security policy.
7. Click File >> Install Policy on SG Appliance.)
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93419r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94233'
  tag rid: 'SV-104187r1_rule'
  tag stig_id: 'SYMP-AG-000090'
  tag gtitle: 'SRG-NET-000019-ALG-000019'
  tag fix_id: 'F-100349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
