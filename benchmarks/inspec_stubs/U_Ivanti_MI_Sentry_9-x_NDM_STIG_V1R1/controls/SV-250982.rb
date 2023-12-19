control 'SV-250982' do
  title 'MobileIron Sentry must limit the number of concurrent sessions for the CLISH interface to an organization-defined number for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Verify that the CLISH has a max number of SSH sessions enabled. 

1. Log in to the Sentry System Manager.
2. Go to Settings >> CLI.
3. Verify a Max SSH Sessions integer (1-10) is set based on security guidance.

If the Max SSH Sessions integer is not set correctly, this is a finding.'
  desc 'fix', 'Configure the CLISH with a max number of SSH sessions. 

1. Log in to the Sentry System Manager.
2. Go to Settings >> CLI.
3. Configure a Max SSH Sessions integer (1-10) based on security guidance.
4. Click "Apply" and "Save" in the top right corner.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54417r802166_chk'
  tag severity: 'medium'
  tag gid: 'V-250982'
  tag rid: 'SV-250982r802168_rule'
  tag stig_id: 'MOIS-ND-000020'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-54371r802167_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
