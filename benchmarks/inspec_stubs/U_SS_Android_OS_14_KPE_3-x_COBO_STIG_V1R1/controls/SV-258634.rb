control 'SV-258634' do
  title 'Samsung Android must be configured to enable a screen-lock policy that will lock the display after a period of inactivity - Disable trust agents.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling Trust Agents.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify "Trust Agents" are set to "Disable".

On the Samsung Android device: 
1. Open Settings >> Security and privacy >> More security settings >> Trust agents.
2. Verify all listed Trust Agents are disabled and cannot be enabled. If a Trust Agent is not disabled in the list, verify for that Trust Agent, all of its listed Trustlets are disabled and cannot be enabled.

If on the management tool "Trust Agents" are not set to "Disable", or on the Samsung Android device a "Trust Agent" or "Trustlet" can be enabled, this is a finding.

Note: If the management tool has been correctly configured but a Trust Agent is still enabled, configure the "List of approved apps listed in managed Google Play" to disable it; refer to KNOX-14-110190.

Exception: Trust Agents may be used if the Authorizing Official (AO) allows a screen lock timeout after four hours (or more) of inactivity. This may be applicable to tactical use case.'
  desc 'fix', 'Configure the Samsung Android devices to disable Trust Agents.

On the management tool, in the device restrictions, set "Trust Agents" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62374r931100_chk'
  tag severity: 'medium'
  tag gid: 'V-258634'
  tag rid: 'SV-258634r931102_rule'
  tag stig_id: 'KNOX-14-110090'
  tag gtitle: 'PP-MDF-333030'
  tag fix_id: 'F-62283r931101_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
