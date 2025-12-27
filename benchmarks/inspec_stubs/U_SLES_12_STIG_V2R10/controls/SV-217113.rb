control 'SV-217113' do
  title 'The SUSE operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'SUSE operating system management includes the ability to control the number of users and user sessions that utilize a SUSE operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to Denial-of-Service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.'
  desc 'check', 'Verify the SUSE operating system limits the number of concurrent sessions to 10 for all accounts and/or account types by running the following command:

# grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf

The result must contain the following line:

* hard maxlogins 10

If the "maxlogins" item is missing, the line does not begin with a star symbol, or the value is not set to "10" or less, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to limit the number of concurrent sessions to 10 or less for all accounts and/or account types.

Add the following line to "/etc/security/limits.conf" or /etc/security/limits.d/*.conf file:

* hard maxlogins 10'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18341r902832_chk'
  tag severity: 'low'
  tag gid: 'V-217113'
  tag rid: 'SV-217113r902834_rule'
  tag stig_id: 'SLES-12-010120'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-18339r902833_fix'
  tag 'documentable'
  tag legacy: ['V-77069', 'SV-91765']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
