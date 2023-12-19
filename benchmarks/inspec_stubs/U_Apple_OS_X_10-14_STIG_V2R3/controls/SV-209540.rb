control 'SV-209540' do
  title 'The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060.

'
  desc 'check', 'For systems that allow remote access through SSH, run the following command to verify that "/etc/banner" is displayed before granting access:

# /usr/bin/grep Banner /etc/ssh/sshd_config

If the sshd Banner configuration option does not point to "/etc/banner", this is a finding.'
  desc 'fix', 'For systems that allow remote access through SSH, modify the "/etc/ssh/sshd_config" file to add or update the following line:

Banner /etc/banner'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9791r282102_chk'
  tag severity: 'medium'
  tag gid: 'V-209540'
  tag rid: 'SV-209540r610285_rule'
  tag stig_id: 'AOSX-14-000024'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-9791r282103_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007']
  tag 'documentable'
  tag legacy: ['V-95819', 'SV-104957']
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
