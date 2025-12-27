control 'SV-241208' do
  title 'Samsung Android must be configured to not allow backup of all applications, configuration data to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review Samsung Android configuration settings to determine if the capability to back up to a locally connected system has been disabled. 

Disabling backup to locally connected systems is implemented by the configuration policy rule "USB file transfer", which is included in KNOX-10-003400.

For KPE(AE) deployments this configuration is the default configuration. If the management tool does not provide the capability to configure "USB file transfer", there is NO finding because the default setting cannot be changed.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "USB file transfer" has been set to "Disallow".

On the PC, browse the mounted Samsung Android device and verify that it does not display any folders or files.

If on the management tool "USB file transfer" is not set to "Disallow", or the PC can mount and browse folders and files on the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable backup to locally connected systems.

For KPE(AE) deployments this configuration is the default configuration. No configuration is required.

Disabling backup to locally connected systems is implemented by the configuration policy rule "USB file transfer", which is included in KNOX-10-003400.

On the management tool, in the device restrictions section, set "USB file transfer" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44484r680263_chk'
  tag severity: 'medium'
  tag gid: 'V-241208'
  tag rid: 'SV-241208r680265_rule'
  tag stig_id: 'KNOX-10-003600'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-44443r680264_fix'
  tag 'documentable'
  tag legacy: ['SV-109049', 'V-99945']
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
