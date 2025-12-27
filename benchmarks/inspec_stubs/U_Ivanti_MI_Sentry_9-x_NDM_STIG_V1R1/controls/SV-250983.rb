control 'SV-250983' do
  title 'MobileIron Sentry must be configured to limit the network access of the Sentry System Manager Portal behind the corporate firewall and whitelist source IP range.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Verify that a secondary interface has been added for System Manager Portal Access of Sentry.

1. Log in to the Sentry System Manager.
2. Go to Settings >> Network >> Interfaces.
3. Verify a Management Interface for internal access of the System Manager Portal has been added as one of the interfaces.

If the Management Interface for internal access of the System Manager Portal has not been added as one of the Interfaces, this is a finding.'
  desc 'fix', 'Configure a secondary interface for System Manager Portal Access of Sentry.

1. Log in to the Sentry System Manager.
2. Go to Settings >> Network >> Interfaces.
3. Click an open Physical Interface such as GigabitEthernet2.
4. Configure a Management Interface for internal access of the System Manager Portal (refer to the "MobileIron Standalone Sentry 9.8.0 Installation Guide" Physical Interfaces section for more information).'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54418r802169_chk'
  tag severity: 'medium'
  tag gid: 'V-250983'
  tag rid: 'SV-250983r802171_rule'
  tag stig_id: 'MOIS-ND-000030'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-54372r802170_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
