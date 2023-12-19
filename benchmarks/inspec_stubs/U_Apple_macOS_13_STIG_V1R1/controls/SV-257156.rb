control 'SV-257156' do
  title 'The macOS system must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via SSH.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060.

'
  desc 'check', 'If SSH is not being used, this is not applicable.

Verify the macOS system is configured to display the contents of "/etc/banner" before granting access to the system with the following command:

/usr/bin/grep -r Banner /etc/ssh/sshd_config*

Banner /etc/banner

If the sshd Banner configuration option does not point to "/etc/banner", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure the macOS system to display the contents of "/etc/banner" before granting access to the system with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^#Banner.*/Banner \/etc\/banner/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60841r905099_chk'
  tag severity: 'medium'
  tag gid: 'V-257156'
  tag rid: 'SV-257156r905101_rule'
  tag stig_id: 'APPL-13-000024'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-60782r905100_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
