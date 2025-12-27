control 'SV-254729' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) server must be configured to enable FIPS mode.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised due to weak algorithms. In addition, the application must be configured to use the FIPS version of all cryptographic algorithms and modules.'
  desc 'check', 'Verify FIPS Mode is enabled for BEMS.

1. Under BEMS Systems Settings select "BEMS Configuration".
2. Select "FIPS Mode".
3. Confirm "Enable FIPS Mode for Cluster" has been selected.

If "Enable FIPS Mode for Cluster" is not selected, this is a finding.'
  desc 'fix', 'Enable FIPS Mode for BEMS.

1. In the BEMS Dashboard, under "BEMS Configuration", click "FIPS Mode".
2. Check the box "Enable FIPS Mode for Cluster".
3. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58340r861910_chk'
  tag severity: 'medium'
  tag gid: 'V-254729'
  tag rid: 'SV-254729r879616_rule'
  tag stig_id: 'BEMS-03-014800'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-58286r861911_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
