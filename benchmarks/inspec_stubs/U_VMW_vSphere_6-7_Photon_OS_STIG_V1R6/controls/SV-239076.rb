control 'SV-239076' do
  title 'The Photon operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service attacks.'
  desc 'check', 'At the command line, execute the following command:

#  grep "^[^#].*maxlogins.*" /etc/security/limits.conf

Expected result:

*              hard    maxlogins      10

If the output does not match the expected result, this is a finding.

Note: The expected result may be repeated multiple times.'
  desc 'fix', "At the command line, execute the following command:

# echo '*              hard    maxlogins      10' >> /etc/security/limits.conf"
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42287r675034_chk'
  tag severity: 'medium'
  tag gid: 'V-239076'
  tag rid: 'SV-239076r877399_rule'
  tag stig_id: 'PHTN-67-000004'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-42246r675035_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
