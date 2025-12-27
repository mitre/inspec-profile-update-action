control 'SV-241215' do
  title 'Samsung Android must be configured to disable multi-user modes (tablets only).'
  desc 'Note: This requirement is only applicable to Samsung tablets.

Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Review Samsung Android configuration settings to determine if multi-user mode is disabled.

KPE(Legacy) deployments only: For KPE(AE) deployments this requirement is inherently met.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device KPE Multiuser section, verify that "Multi-user mode" is set to "Disallow".

On the Samsung Android device, open Settings and verify that the "User" setting is not listed.

If on the management tool "Multi-user mode" is not set to "Disallow", or on the Samsung Android device the "User" setting is available, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable multi-user modes.

KPE(Legacy) deployments only: For KPE(AE) deployments this requirement is inherently met.

On the management tool, in the device KPE Multiuser section, set "Multi-user mode" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44491r680284_chk'
  tag severity: 'medium'
  tag gid: 'V-241215'
  tag rid: 'SV-241215r852775_rule'
  tag stig_id: 'KNOX-10-005000'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-44450r680285_fix'
  tag 'documentable'
  tag legacy: ['SV-109063', 'V-99959']
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
