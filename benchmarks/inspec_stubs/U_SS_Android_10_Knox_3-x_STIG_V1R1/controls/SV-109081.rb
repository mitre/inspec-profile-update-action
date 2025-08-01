control 'SV-109081' do
  title 'Samsung Android must be configured to enable Knox CC Mode.'
  desc 'The KPE CC Mode feature is a superset of other features and behavioral changes that are mandatory MDFPP requirements. If CC mode is not implemented the device will not be operating in the NIAP-certified compliant CC Mode of operation.

CC Mode implements the following behavioral/functional changes:

- FOTA signature verification uses additional SHA-512 signature check.
- Download Mode is disabled and all updates will occur via FOTA only.
- IKEv1 operates in Main Mode only.
- HTTPS audit logging in enabled.
- Certificates without a Subject Alternative Name (SAN) field are rejected.
- Certificates that do not pass Strict Host Name verification are rejected.
- Certificates provided by servers must have the Extended Key Usage field set as Server Authentication.
- Allows only authenticated Bluetooth connections.
- Additional Key Zeroization is performed.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android configuration settings to determine if KPE CC Mode is enabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device KPE restrictions section, verify that "CC mode" is set to "Enable".

On the Samsung Android device, put the device into "Download mode" and verify that the text "Blocked by CC Mode" is displayed on the screen.

If on the management tool "CC mode" is not set to "Enable", or on the Samsung Android device the text "Blocked by CC Mode" is not displayed in "Download mode", this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable KPE CC Mode.

On the management tool, in the device KPE restrictions section, set "CC mode" to "Enable".'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98827r1_chk'
  tag severity: 'high'
  tag gid: 'V-99977'
  tag rid: 'SV-109081r1_rule'
  tag stig_id: 'KNOX-10-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-105661r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
