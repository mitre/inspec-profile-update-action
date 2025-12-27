control 'SV-91093' do
  title 'Kona Site Defender must immediately use updates made to policy enforcement mechanisms to block traffic from organizationally defined IP addresses (i.e., IP blacklist).'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the PPSM CAL, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.

Changes to the ALG must take effect when made by an authorized administrator and the new configuration is put in place or committed, including upon restart of the application or reboot of the system. With some devices, the changes take effect as the configuration is changed, while with others, the new configuration must be submitted to the device. In any case, the behavior of the ALG must immediately be affected to reflect the configuration change.'
  desc 'check', 'Confirm Kona Site Defender is configured to block traffic for organizationally defined IP addresses:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted for which product to use, select "Site Defender" and then "Continue".
5. Under the "Security Configurations" section, click on the most recent version under the "Production" column for the security configuration being reviewed.
6. The detailed "Security Configuration" page will load listing the protected host names and applicable policies.
7. Select the policy being reviewed.
8. Verify the "Network Layer Controls" checkbox is enabled.
9. Within the "Network Layer Controls Configuration" section, verify the organizationally defined IP address appear in the "Blocked IPs" area, and the applicable predefined network lists appear in the "Blocked IP Network Lists" area.

If the Network Layer Controls are not enabled and the organizationally defined IP addresses/network lists do not appear in the lists area, this is a finding.'
  desc 'fix', 'Configure the Kona Site Defender to block traffic for organizationally defined IP addresses:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted for which product to use, select "Site Defender" and then "Continue".
5. Under the "Security Configurations" sections, click on the most recent version under the "Production" column for the security configuration being reviewed.
6. The detailed "Security Configuration" page will load listing the protected host names and applicable policies.
7. Select the policy being reviewed, click the "Edit" button, and enable the "Network Layer Controls" box.
8. Select the "IP Controls" tab and add the blocked IP addresses.
9. Select the "Network Lists" tab and add/select the blocked network lists.
10. Click the "Save" button and the "Next" button and follow the prompts to complete the process.'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76053r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76397'
  tag rid: 'SV-91093r1_rule'
  tag stig_id: 'AKSD-WF-000004'
  tag gtitle: 'SRG-NET-000019-ALG-000019'
  tag fix_id: 'F-83073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
