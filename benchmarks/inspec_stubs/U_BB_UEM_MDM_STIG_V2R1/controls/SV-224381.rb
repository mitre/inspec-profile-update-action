control 'SV-224381' do
  title 'The BlackBerry UEM server must be maintained at a supported version.'
  desc 'Versions of BlackBerry UEM are maintained by BlackBerry for specific periods of time. Unsupported versions will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

A list of supported UEM versions is maintained by BlackBerry here: https://www.blackberry.com/us/en/support/software-support-life-cycle.

SFR ID: FPT_TUD_EXT.1'
  desc 'check', 'Review the UEM console version, via the help page. Correlate the version with the latest supported version of UEM.

If the installed version of UEM is not a supported version, this is a finding.'
  desc 'fix', 'The administrator must check https://www.blackberry.com/uk/en/support/software-support-life-cycle for the latest supported and unsupported versions of software.

Once confirmed, the administrator must update BlackBerry UEM to the latest supported version after the following reupgrade tasks: https://docs.blackberry.com/en/endpoint-management/blackberry-uem/12_12/installation-configuration/installation-and-upgrade/ksa1400184024142 & https://docs.blackberry.com/en/endpoint-management/blackberry-uem/12_12/installation-configuration/installation-and-upgrade/ksa1400184232267/ksa1420584119147.'
  impact 0.7
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26058r539043_chk'
  tag severity: 'high'
  tag gid: 'V-224381'
  tag rid: 'SV-224381r604136_rule'
  tag stig_id: 'BUEM-00-000730'
  tag gtitle: 'PP-MDM-992000'
  tag fix_id: 'F-26046r539044_fix'
  tag 'documentable'
  tag legacy: ['SV-111879', 'V-102917']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
