control 'SV-91087' do
  title 'Kona Site Defender must immediately use updates made to policy enforcement mechanisms to enforce that all traffic flows over HTTPS port 443.'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the PPSM CAL, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.

Changes to the ALG must take effect when made by an authorized administrator and the new configuration is put in place or committed, including upon restart of the application or reboot of the system. With some devices, the changes take effect as the configuration is changed, while with others, the new configuration must be submitted to the device. In any case, the behavior of the ALG must immediately be affected to reflect the configuration change.'
  desc 'check', 'Confirm Kona Site Defender is configured to enforce all traffic flows over HTTPS port 443:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Select Group or Property" button.
3. Select the configuration that is being reviewed.
4. Under the "Active Production" section, click on the active version.
5. In the "Property Version Information" section, verify the "Security Options" check box is checked.

If the "Security Options" check box in "Property Manager" is not configured to enforce all traffic flows over HTTPS port 443, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to enforce all traffic flows over HTTPS port 443:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Select Group or Property" button.
3. Select the configuration that is being reviewed.
4. Under the "Active Production" section, click on the active version.
5. On the "Property Manager Editor" screen, click the "Edit New Version" button.
6. In the "Property Version Information" section, enable the "Security Options" check box.
7. Click the "Save" button.
8. Select the "Activate" tab and push the configuration to production.'
  impact 0.7
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76047r1_chk'
  tag severity: 'high'
  tag gid: 'V-76391'
  tag rid: 'SV-91087r1_rule'
  tag stig_id: 'AKSD-WF-000001'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-83067r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
