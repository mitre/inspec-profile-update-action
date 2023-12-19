control 'SV-239447' do
  title 'The SLES for vRealize must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', %q(Verify the SLES for vRealize limits the number of concurrent sessions to "10" for all accounts and/or account types with the following command:

# grep maxlogins /etc/security/limits.conf  | grep -v '#' 

The default maxlimits should be set to a max of "10" or a documented site defined number:

* hard    maxlogins      10

If the default maxlimits is not set to "10" or the documented site defined number, this is a finding.)
  desc 'fix', %q(Configure the SLES for vRealize to limit the number of concurrent sessions to "10" for all accounts and/or account types by using the following command:

sed -i 's/\(^* *hard *maxlogins\\).*/*              hard    maxlogins      10/g' /etc/security/limits.conf)
  impact 0.3
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42680r661790_chk'
  tag severity: 'low'
  tag gid: 'V-239447'
  tag rid: 'SV-239447r877399_rule'
  tag stig_id: 'VROM-SL-000040'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-42639r661791_fix'
  tag 'documentable'
  tag legacy: ['SV-99015', 'V-88365']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
