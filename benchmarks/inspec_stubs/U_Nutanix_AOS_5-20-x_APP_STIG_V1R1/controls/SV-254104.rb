control 'SV-254104' do
  title 'Nutanix AOS must provide an immediate warning to the SA and ISSO, at a minimum, when allocated log record storage volume reaches 75 percent of maximum log record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. Notification of the storage condition will allow administrators to take actions so that logs are not lost. This requirement can be met by configuring the application server to utilize a dedicated logging tool that meets this requirement.

'
  desc 'check', 'Confirm Nutanix Cluster Check (NCC) "CVM DISK | System Audit Volume Usage" is enabled and the threshold values are set correctly.

1. Log in to Prism Element.
2. Select "Health dashboard" from navigation dropdown.
3. Select Actions >> Manage Checks.
4. Scroll down to CVM | Disk section, and then select "System Audit Volume Usage".

If the selected check is Disabled, this is a finding.

Validate the Alert Policy settings for Warning and Critical are set to 75 percent.

If the Warning or Critical values are not set to 75 percent, this is a finding.'
  desc 'fix', 'Configure Nutanix Cluster Check (NCC) "CVM DISK | System Audit Volume Usage" is enabled and the threshold values are set to organization-defined values.

1. Log in to Prism Element.
2. Select "Health dashboard" from navigation dropdown.
3. Select Actions >> Manage Checks.
4. Scroll down to CVM | Disk section, select "System Audit Volume Usage".
5. If check is disabled, click to enable the check.
6. Select "Alert Policy", set the values for "Warning" and "Critical" thresholds to 75 percent and click "Save".'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57589r846398_chk'
  tag severity: 'medium'
  tag gid: 'V-254104'
  tag rid: 'SV-254104r846400_rule'
  tag stig_id: 'NUTX-AP-000130'
  tag gtitle: 'SRG-APP-000359-AS-000065'
  tag fix_id: 'F-57540r846399_fix'
  tag satisfies: ['SRG-APP-000359-AS-000065', 'SRG-APP-000360-AS-000066']
  tag 'documentable'
  tag cci: ['CCI-001855', 'CCI-001858']
  tag nist: ['AU-5 (1)', 'AU-5 (2)']
end
