control 'SV-209615' do
  title 'The macOS system must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'To view the setting for the smartcard certification configuration, run the following command:

sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard

If the return is not "enforceSmartCard = 1;" this is a finding.'
  desc 'fix', 'For stand-alone systems, this setting is enforced using the "Smart Card Policy" configuration profile.

Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9866r466270_chk'
  tag severity: 'medium'
  tag gid: 'V-209615'
  tag rid: 'SV-209615r610285_rule'
  tag stig_id: 'AOSX-14-003005'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-9866r466271_fix'
  tag 'documentable'
  tag legacy: ['SV-105099', 'V-95961']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
